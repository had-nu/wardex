# REC + Provenance: Análise de Resiliência e Plano de Mitigação v2.2.3

> **REC** = Registro Encadeado Criptografado (Chained Audit Log)
> **Provenance** = 3CP (Cryptographic Chain of Custody Protocol) via Gleipnir reference implementation
>
> **Status**: Este documento foi o plano original para v2.2.3. As secções marcadas com ✓ foram
> implementadas na v2.3.0 com a migração CBOR determinística e pacote `pkg/attest/`. As secções
> marcadas com △ permanecem como planeamento para versões futuras.

---

## 1. Estado Atual da Resiliência

### 1.1 Chained Audit Log (REC)

**Resiliente:**
- SHA-256 hash chain — adulteração de qualquer entrada é detectada por `VerifyChain()`
- Detecção de **modificação** e **remoção** de entradas
- Arquivo com permissão `0600` (só o dono)
- Escrita thread-safe via `sync.Mutex`
- `SafePath` contra path traversal
- Multi-segmentos (cada sessão começa com gênese)

**Não resiliente:**

| Limitação | Impacto |
|-----------|---------|
| **Arquivo único no disco** | Atacante com acesso ao FS pode deletar/substituir o arquivo inteiro |
| **Sem âncora temporal externa** | Provas auto-referenciadas — não há testemunha externa atestando *quando* cada entrada foi criada |
| **Sem replicação** | Perda do disco = perda do log (sem backup externo) |
| **Sem lock cross-process** | CI/CD paralelo corrompe a cadeia (detectável, mas corrompe) |
| **Sem log rotation** | Crescimento infinito; verificação fica O(n) sobre o arquivo inteiro |

### 1.2 State Store (BLAKE3 Chain)

| Limitação | Impacto |
|-----------|---------|
| **Race condition sem detecção** | Dois processos paralelos: ambos carregam `chain.json`, cada um dá `AppendEntry`, o segundo a salvar **sobrescreve** a entrada do primeiro. Perda silenciosa de dados. |

### 1.3 CLI verify-chain — Bug de Compatibilidade

**Descoberto durante a análise:**

O REC gerado por `ChainedAuditLog` escreve o campo `previous_entry_hash` no JSON.
O CLI `wardex audit verify-chain` lê o campo `prev_hash` (formato CPL).

Efeito: um audit log válido gerado por `wardex evaluate` é reportado como **TAMPERED**
pelo CLI porque o campo `prev_hash` não existe nas entradas — apenas `previous_entry_hash`.

A verificação interna (`pkg/accept.VerifyChain`) funciona corretamente.
A verificação via CLI (`cmd/audit/verify_chain.go`) produz **falso positivo** para logs REC.

Os dois formatos precisam ser unificados.

---

## 2. Como o Provenance (v2.3) Pode Reforçar o REC

O módulo de provenance (3CP via Gleipnir) tem 4 conceitos adaptáveis ao REC:

### 2.1 Merkle Root sobre Conjunto de Dados

**No provenance**: `ComputeRootHash()` percorre arquivos ordenados,
computa `SHA-256(path|hash\n)` para cada um, produz um root hash único
representando todo o manifesto.

**Aplicado ao REC**: Um **segment root hash** calculado sobre N entradas do
audit log. Em vez de cada entrada ser um elo individual, o segmento inteiro
vira um "bloco". O root hash é commitado como entrada especial
(`event: segment.sealed`).

Benefícios:
- Permite **log rotation com integridade**: arquiva o segmento velho,
  o root hash fica na cadeia
- Acelera verificação: confere o root hash do segmento em vez de re-hash
  cada linha
- Torna viável podar histórico sem perder a prova

### 2.2 OpenTimestamps (Âncora Bitcoin)

**No provenance**: `ots.go` envia SHA-256 do manifesto para calendários
públicos, produzindo receipt `.ots` comprovando existência antes de um bloco
Bitcoin.

**Aplicado ao REC**: O root hash de cada segmento (ou a cada N segmentos)
é enviado ao OTS. Resolve a **falta de prova temporal externa**:
- Não precisa ancorar cada entrada individual (caro)
- Ancoragem periódica do segment root hash já prova que TODAS as entradas
  daquele segmento existiam antes do timestamp Bitcoin

### 2.3 Contrato Ethereum (ProvenanceAnchor.sol)

**No provenance**: `ethanchor.go` chama o contrato `ProvenanceAnchor.sol`
que emite evento `Anchored(bytes32 rootHash, uint256 timestamp)` na
blockchain.

**Aplicado ao REC**: O root hash do segmento é registrado na Ethereum/Polygon
como prova pública e replicada. Qualquer auditor verifica independentemente.

### 2.4 Assinatura Ed25519 ✓

**No provenance (v2.3.0)**: `pkg/attest/attestation.go` gera CBOR determinístico
do `ToolAttestation` → `SignWithEd25519()`, provando autoria e integridade.
Usa `cbor.CanonicalEncOptions()` + `cbor.TimeRFC3339` para garantir
byte-identicidade entre plataformas.

**Aplicado ao REC (△)**: Cada segment seal pode ser assinado com o mesmo
mecanismo. O `signed_by` e `sig` no `SealEntry` seguem o formato do
`SignedAttestation`.

### 2.5 Matriz: Provenance → REC Weaknesses

| Weakness do REC | Provenance Element | Como Resolve |
|----------------|-------------------|--------------|
| Sem prova temporal externa | OTS + Eth anchor | Root hash do segmento na blockchain |
| Log rotation impossível | Merkle root + segment seal | Sela segmento, arquiva, começa novo |
| Verificação lenta (O(n)) | Merkle root por segmento | Verificação O(1) por segmento |
| Não-repúdio ausente | Ed25519 signing | Assina cada segment seal |
| Quem selou o quê | Author identity + pubkey | Metadados no seal |

---

## 3. Plano de Mitigação Detalhado — v2.2.3

### 3.1 Resumo das Entregas

```
v2.2.3 — Integridade Operacional do REC
├── 3.2 Flock: lock cross-process (crítico)
├── 3.3 Unificação do formato da chain (dívida técnica)
├── 3.4 Segment seal + log rotation
├── 3.5 CLI verify-chain atualizado
└── 3.6 Testes de concorrência
```

### 3.2 Cross-Process Locking (flock)

**Problema**: `sync.Mutex` protege apenas goroutines no mesmo processo.
CI/CD paralelo corrompe o log (REC) e perde dados (state store).

**Solução**: Adicionar `flock(2)` via `golang.org/x/sys/unix` com fallback
para Windows (lock file).

**Package `pkg/lock/` — API**:

```go
package lock

// Lock adquire lock exclusivo no path, criando o arquivo se necessário.
// Bloqueia até adquirir. Retorna o handle.
func Lock(path string) (*Handle, error)

// Handle encapsula *os.File com lock ativo.
type Handle struct { ... }

// Unlock libera o lock e fecha o arquivo.
func (h *Handle) Unlock() error

// WithLock executa fn enquanto segura o lock.
func WithLock(path string, fn func() error) error
```

**Arquivos**:

| Arquivo | Build Tag | Implementação |
|---------|-----------|---------------|
| `pkg/lock/flock.go` | — | Interface + `WithLock()` |
| `pkg/lock/flock_linux.go` | `linux` | `syscall.Flock(fd, LOCK_EX)` |
| `pkg/lock/flock_darwin.go` | `darwin` | `syscall.Flock(fd, LOCK_EX)` |
| `pkg/lock/flock_other.go` | `!linux,!darwin` | Lock file via `os.Create` + spin |
| `pkg/lock/flock_test.go` | — | Testes de lock concorrente |

**Modificação no REC** (`pkg/accept/chain.go`):

```go
func ChainedAuditLog(logPath string, entry model.AuditEntry) error {
    // Adquire lock cross-process antes de read-modify-write
    return lock.WithLock(logPath+".lock", func() error {
        prevHash, err := lastEntryHashLocked(logPath)
        // ... resto igual ...
    })
}
```

**Modificação no State Store** (`pkg/statestore/store.go`):

```go
func (s *Store) SaveState(state *State) error {
    lockPath := filepath.Join(s.root, ".lock")
    return lock.WithLock(lockPath, func() error {
        // atomicWrite(state.json) + AppendEntry + SaveChain
    })
}
```

### 3.3 Unificação do Formato da Chain

**Problema**: Dois formatos incompatíveis:
- REC: campo `previous_entry_hash`, gênese = `""`
- CPL: campo `prev_hash`, gênese = `"genesis"`
- CLI `verify-chain` só entende CPL → falso positivo em logs REC

**Solução**: Adotar `prev_hash` como canônico. `PreviousEntryHash` vira
deprecated.

**Transição**:

| Versão | Comportamento |
|--------|---------------|
| v2.2.2 | Só escreve `previous_entry_hash` |
| v2.2.3 | Escreve **ambos** (`prev_hash` + `previous_entry_hash`) |
| v2.4+ | Remove `previous_entry_hash`, mantém só `prev_hash` |

**Arquivos**:

| Arquivo | Mudança |
|---------|---------|
| `pkg/model/audit.go` | `PrevHash` preenchido pelo REC; `PreviousEntryHash` marcado `deprecated` |
| `pkg/accept/chain.go` | `ChainedAuditLog` seta ambos os campos |
| `pkg/accept/chain.go` | `VerifyChain` aceita ambos os campos para leitura |

### 3.4 Segment Seal + Log Rotation

**Problema**: JSONL cresce indefinidamente. Sem rotação ou archive.

**Solução**: Mecanismo de checkpoint por segmento, inspirado no
`ComputeRootHash` do provenance.

**Package `pkg/segment/` — API**:

```go
package segment

// ComputeSegmentRoot calcula root hash Merkle-like sobre entries ordenadas.
// SHA-256("entry_hash|index\n") para cada entrada.
func ComputeSegmentRoot(entries []model.AuditEntry) string

// SealConfig define quando rotacionar.
type SealConfig struct {
    MaxEntries int    // dispara rotação ao atingir N entradas (default: 10000)
    ArchiveDir string // diretório para arquivar segmentos selados
    SignKey    string // caminho para chave Ed25519 (opcional)
}

// SealEntry é a entrada especial que sela um segmento.
type SealEntry struct {
    Timestamp     time.Time `json:"ts"`
    Event         string    `json:"event"`         // "segment.sealed"
    PrevHash      string    `json:"prev_hash"`
    SegmentIndex  int       `json:"segment_index"`
    SegmentRoot   string    `json:"segment_root"`
    SegmentEntries int      `json:"segment_entries"`
    SegmentFile   string    `json:"segment_file"`
    SignedBy      string    `json:"signed_by,omitempty"`
    Sig           string    `json:"sig,omitempty"`
}

// OpenEntry é a primeira entrada de um novo segmento.
type OpenEntry struct {
    Timestamp        time.Time `json:"ts"`
    Event            string    `json:"event"`              // "segment.open"
    PrevHash         string    `json:"prev_hash"`          // "genesis"
    SegmentIndex     int       `json:"segment_index"`
    PrevSegmentRoot  string    `json:"prev_segment_root"`
    PrevSegmentFile  string    `json:"prev_segment_file"`
}
```

**Algoritmo de Rotação** (em `pkg/accept/chain.go`):

```
func CheckpointAndRotate(logPath string, cfg segment.SealConfig) error:
    1. lock(logPath + ".lock")
    2. Ler entries atuais
    3. Se len(entries) < cfg.MaxEntries → retornar (sem rotação necessária)
    4. Computar SegmentRoot(entries)
    5. Adicionar entry "segment.sealed" com root_hash, signed_by, etc
    6. Renomear logPath → ArchiveDir/wardex-gate-audit-YYYY-MM-DT-HH-MM-SS.log
    7. Criar novo logPath com entry "segment.open" que referencia o segmento anterior
       (prev_hash="genesis", prev_segment_root=<root>, prev_segment_file=<nome>)
```

**Trigger**: Chamado automaticamente no `ChainedAuditLog` quando o arquivo
atual atinge `max_segment_entries`.

**Config** (`config/config.go`):

```go
type AuditLogConfig struct {
    Path              string `yaml:"path"`                // atual default
    MaxSegmentEntries int    `yaml:"max_segment_entries"` // default: 10000, 0 = desliga
    ArchiveDir        string `yaml:"archive_dir"`         // default: ".wardex/audit-archive"
    SignWithKey       string `yaml:"sign_with_key"`       // opcional, chave Ed25519
}
```

Adicionar ao `Config`:

```go
type Config struct {
    // ... campos existentes ...
    AuditLog AuditLogConfig `yaml:"audit_log"` // NEW v2.2.3
}
```

### 3.5 CLI verify-chain Atualizado

**Problema**: `wardex audit verify-chain` lê `prev_hash` mas REC escreve
`previous_entry_hash`.

**Solução**: Detectar ambos os campos + verificar segment seals.

**Mudanças em `cmd/audit/verify_chain.go`**:

- `splitSegments`: detecta ambos `prev_hash` e `previous_entry_hash`
- Adicionar flag `--segment` para verificação segmento-a-segmento
- Adicionar `--archive-dir` para incluir arquivos de segmento na verificação
- Verificar cross-segment links (segment.open → prev_segment_root)

### 3.6 Testes de Concorrência

**Arquivos**:

| Arquivo | O que testa |
|---------|-------------|
| `pkg/lock/flock_test.go` | Lock/unlock, lock concorrente com timeout, lock entre processos |
| `pkg/accept/audit_chain_race_test.go` | 10 goroutines paralelas + 3 processos reais (`os.Exec`) no mesmo log |
| `pkg/statestore/chain_race_test.go` | 10 goroutines + 3 processos, verifica sem perda de dados |
| `pkg/segment/segment_test.go` | Rotation no limite correto, cross-segment verify, archive integrity |

---

## 4. Prioridade e Esforço

| Item | Esforço | Impacto | Complexidade | Ordem |
|------|---------|---------|-------------|-------|
| 3.2 Flock | Médio | 🔴 Crítico | Média (portabilidade) | 1º |
| 3.3 Unificação formato | Pequeno | 🟡 Médio | Baixa | 2º |
| 3.6 Testes concorrência | Médio | 🔴 Crítico | Média | 3º |
| 3.5 CLI verify-chain | Pequeno | 🟡 Médio | Baixa | 4º |
| 3.4 Segment seal + rotation | Alto | 🟢 Alto | Média-alta | 5º |

**Ordem de implementação**: 3.2 → 3.3 → 3.6 → 3.5 → 3.4

---

## 5. Implementado na v2.3.0

O que foi realizado como parte da migração CBOR + 3CP:

- [x] **CBOR determinístico** para CPL canonicalization (`internal/cpl/cbor.go`)
- [x] **WexState v2** com CBOR deterministic sealing (`pkg/trust/wexstate_cbor.go`)
- [x] **`pkg/attest/`** — Tool attestation com Ed25519 + CBOR (`pkg/attest/attestation.go`)
- [x] **CDDL schemas** em `spec/cddl/` (cpl-entry, wexstate, tool-attestation)
- [x] **CLI `wardex provenance attest`** (`cmd/provenance/attest.go`)
- [x] **Converters com `--attest`** (`cmd/convert/grype.go`, `cmd/convert/kev_cmd.go`,
      `cmd/convert/sbom.go`)
- [x] **3CP abstraction** — interface `Anchorer` + backends embedded/gRPC/noop
      (`pkg/provenance/`)

## 6. Próximos Passos (△)

Itens do plano original que permanecem como planeamento:

- [ ] △ Integrar `pkg/segment` com OTS: enviar segment root hash para
      OpenTimestamps
- [ ] △ Integrar `pkg/segment` com Ethereum anchor: registrar segment root hash
      no `ProvenanceAnchor.sol`
- [ ] △ CLI `wardex provenance seal --audit-log` para selar manualmente
- [ ] △ CLI `wardex provenance verify --audit-log` para verificar âncora blockchain
- [ ] △ Documentação: playbook de disaster recovery com segmentos + blockchain
