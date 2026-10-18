# SPEC: Wardex v2.6.0 — Nym Patterns (Cadeia, Migração, Gate e Chaves)

**Status:** Draft
**Author:** André Ataíde (had-nu)
**Date:** 2026-09-14
**Target Version:** v2.6.0
**Go Version:** 1.27.0
**Related:** `SPEC_wardex_v2.5.0_go127_hardening.md`, `CBOR_MIGRATION_v2.3.0.md`, `SPEC_v1.9.1_schema_cleanup.md`

---

## 1. Resumo Executivo

Esta especificação transpõe sete padrões do ecossistema Nym (estudado em `0zym/nym/nym-develop/`, 2026-09-14) para o Wardex. O objectivo é **endurecer a prova** que o Wardex produz — "uma decisão foi tomada sobre o estado exacto" — atacando as fragilidades identificadas na própria base de código:

1. O verificador `wardex audit verify-chain` diverge do formato escrito pelo runtime (falso-positivo de tampering em logs reais).
2. O CPL não distingue "conteúdo mudou" de "schema mudou".
3. Chaves geradas por `keygen` ficam em plaintext em repouso.
4. Não existe registo de versões já seladas (relançamento silencioso é possível).
5. Leituras de audit log são unbounded (OOM em logs longos); não há export paginado para SIEM.
6. O gate não distingue classes de risco (PR vs deploy vs nightly).
7. Não há kill-switch com tripwire para deadlines regulatórias.

Os padrões do Nym são aplicados como **referência de desenho**, não como cópia literal: o Wardex é CLI + JSONL offline, sem protocolo ao vivo — por isso a "negociação de capacidades" resume-se à regra de versionamento, e o tripwire assenta nas fontes de evidência do próprio Wardex (EPSS/KEV), **sem dependência funcional do Gleipnir**.

As alterações são **aditivas e retro-compatíveis**: parse de formatos antigos é mantido em todos os pontos; nenhuma quebra de hash de configuração é introduzida (o CPL content-hash permanece estável).

---

## 2. Princípios Adoptados (das lições transversais do estudo Nym)

| # | Princípio | Origem Nym | Aplicação Wardex |
|---|-----------|------------|------------------|
| P1 | Versão explícita por frame | `models.rs`, `store-cipher` `CURRENT_VERSION` | Campos numéricos de versão em artefactos/repositories novos; version strings livres apenas onde já existem |
| P2 | Parse de versões antigas mantido | `api/mod.rs:73-114` (legado de verificação mantido) | Toda mudança de formato preserva leitura do formato anterior |
| P3 | Teste `the_current_version_is_one_we_support` | Nym test suite | Um teste por artefacto com `format_version` |
| P4 | Nunca mutar o ficheiro de origem | `upgrade_helpers.rs` | Migração de config/domain in-memory; grava-se só a versão final |
| P5 | O audit log é a fonte de verdade | — (invariante Wardex) | Índices derivados (registo de versões) são cache reconstruível |
| P6 | Carga-antiga-tentada-primeiro, migra só em falha | `upgrade_helpers.rs:10-47` | Loader com `KnownFields(true)` + fallback leniente v1 |
| P7 | `deny_unknown_fields` para typo em config novo | `nym-node/config/mod.rs:478-502` | `yaml.Decoder.KnownFields(true)` |
| P8 | Gate com classes de risco e deadlines separadas | `ci-cargo-deny.yml` vs `nightly-security-audit.yml` | `--gate-class pr\|deploy\|nightly` |
| P9 | Paginação por cursor `LIMIT+1`, nunca unbounded | `gateway-storage/src/inboxes.rs:23-33` | Iterador streaming + export por cursor |
| P10 | Persistência cifrada em envelope versionado | `common/store-cipher/src/lib.rs` | `pkg/keys` Argon2id + AES-256-GCM opt-in |
| P11 | Kill-switch com tripwire anti-falso-positivo | `upgrade_mode/watcher.rs:19-110` | `forced_upgrade` desarmado por N falhas consecutivas |

---

## 3. Scope

### 3.1. In-Scope

- P0 — Unificação do formato de cadeia do audit log (canónico `previous_entry_hash`, genesis vazio) e correcção do `verify-chain` / `splitSegments`.
- L1 — Migração de configuração encadeada, sem quebra de hash (envelope na `AuditEntry` + loader versionado).
- L2 — Versão numérica + bitmap de capacidades em artefactos de saída (regra P1, sem handshake).
- L3 — Gate por classe de risco (`pr`/`deploy`/`nightly`).
- L4 — Anti-regressão de versão (`check-version`, exit 13) + referência de política obrigatória.
- L5 — Iterador streaming + `wardex audit export` com cursor `LIMIT+1`.
- L6 — `pkg/keys`: envelope Encriptado opt-in para chaves em repouso.
- L7 — `forced_upgrade` kill-switch com tripwire de atestação (sem dependência Gleipnir).
- Update de `spec/cddl/cpl-entry.cddl`, exit codes, README, CHANGELOG.

### 3.2. Out-of-Scope

- Alterações à fórmula de risco/tomada de decisão do `pkg/releasegate`.
- Alteração do content-hash CPL (canonical CBOR intacto — a versão de schema vive no envelope da entrada de audit).
- `SealMessage`/`wexstate` v1/v2 (mantêm-se; sem campos novos no CBOR assinado).
- Protocolo 3CP/Gleipnir: `Anchorer` continua interface opcional pós-evidência; nenhuma dependência funcional nova.
- Migração WexState v1 → numérico (fica para versão futura, natural por envelope).

---

## 4. P0 — Unificação do Formato de Cadeia (pré-requisito)

### 4.1. Problema

O runtime escreve a cadeia com `previous_entry_hash` (`pkg/accept/audit/chain.go:82`, genesis vazio `""`), mas o verificador `wardex audit verify-chain` lê `prev_hash` e exige literal `"genesis"` (`internal/cpl/chain.go:26,33`). `pkg/model/audit.go` carrega ambos os campos (`prev_hash` legado, `previous_entry_hash` primário). O CDDL `spec/cddl/cpl-entry.cddl` documenta o formato `"genesis"`, que o runtime **nunca escreve** — por isso `verify-chain` reporta tampered/gap em logs reais (confirmado no fixture `cmd/art14/wardex-gate-audit.log`).

### 4.2. Decisão

- **Canónico:** `previous_entry_hash`; genesis = campo ausente ou vazio (primeira entrada).
- **Link:** SHA-256 hex do raw bytes da linha JSONL anterior (sem newline), tal como já calculado por `pkg/accept/audit/chain.go:166`.
- **Transição legado (P2):** se uma entrada tiver `prev_hash == "genesis"`, tratar como genesis; se tiver `prev_hash == <hash>`, aceitá-lo como link antigo. `prev_hash` fica **deprecado** no `model.AuditEntry`.

### 4.3. Alterações

- `internal/cpl/chain.go` — `VerifyChain` lê `previous_entry_hash` como campo primário e `prev_hash` como fallback compat; regra de genesis (ausente/vazio OU `"genesis"`); mantém hash sobre a linha crua.
- `cmd/audit/verify_chain.go` — `splitSegments` reparte por genesis canónico (não só pelo literal `"genesis"`); entrada múltipla por segmento mantém-se.
- `spec/cddl/cpl-entry.cddl` — documentar canónico + deprecar `prev_hash`.
- `pkg/model/audit.go` — doc comment de deprecação em `PrevHash`; sem remoção (P2).
- Fixtures em `testdata/fixtures/cpl/`: um log no formato runtime real, um legado `"genesis"`; ambos verificam clean; tamper/gap permanecem detectados.

### 4.4. Testes

- `internal/cpl/chain_test.go`: runtime-format, legacy-format, tamper, gap, malformed JSON.
- `cmd/audit`: verificação de segmentação multi-sessão por ambos os formatos de genesis.

---

## 5. L1 — Migração de Configuração Encadeada (sem quebra de hash)

### 5.1. Decisão (user-approved)

A versão de schema vive no **envelope da entrada de audit**, não no canonical CBOR. O content-hash CPL permanece estável — nenhuma quebra de hash (evita novo procedimento de re-hash tipo v2.3.0).

### 5.2. Design

- `model.AuditEntry` ganha `cpl_schema_version int` (`json:"cpl_schema_version,omitempty"`); ausente = v1.
- `internal/cpl/verifylink.go` — `VerifyLink` valida também que a versão registada bate com a versão de schema esperada no deploy (além do content-hash).
- `internal/policy/` — loader estrito P7 (`KnownFields(true)`); em erro de campo desconhecido → tentar parse leniente v1 (P6). Novo `Migrate(doc, from, to)` declarativo por versão, in-memory, nunca muta o ficheiro (P4).
- `DomainFile` ganha `format_version` (o campo `Version` existente é versão de framework — mantém-se distinto).
- `config/config.go` — manter `KnownFields(true)`; novo `config_schema_version` requerido + `MigrateConfig` declarativo.

### 5.3. Ficheiros

`pkg/model/audit.go` · `internal/cpl/verifylink.go` · `internal/policy/{loader.go,schema.go,migrate.go}` · `config/config.go`

### 5.4. Testes

- Migração v1→v2 com campo desconhecido; origem intacta após migração (P4).
- `verify-link` a falhar em `cpl_schema_version` discrepante.
- `the_current_version_is_one_we_support` para policy e config.

---

## 6. L2 — Versão Numérica + Bitmap de Capacidades

### 6.1. Decisão (reduzida à regra P1)

Sem handshake (não há protocolo ao vivo). Aplicação onde forward-compat importa:

- `pkg/model/art14.go` — `Art14NotificationArtefact` ganha `format_version uint8` + `capabilities uint32`:
  - `bit HMAC_SHA256 = 1<<0`, `bit CANONICAL_JSON = 1<<1`, `bit CBOR_V1 = 1<<2`.
- Versão futura: leitura tolerante; **verificação** reporta erro controlado ("unsupported format, upgrade needed") — nunca clamp silencioso (verificar exige assinatura válida).
- `WexState` mantém v1/v2 string (P2); artefactos novos usam numérico.

### 6.2. Testes

- `TestCurrentArtifactVersionIsSupported` (P3) + parse-legacy `format_version` ausente.

---

## 7. L3 — Gate por Classe de Risco

### 7.1. Design

- Flag `--gate-class pr|deploy|nightly` em `wardex evaluate` + input `gate-class` na `action.yml`.

| Classe | Integridade (3/4) | Política (10/11) | Frescura EPSS/KEV | Actively-exploited (12) |
|--------|-------------------|------------------|-------------------|--------------------------|
| `pr` | bloqueia | bloqueia | **adverte** (exit 6) | alerta (não é path de release) |
| `deploy` | bloqueia | bloqueia | bloqueia | bloqueia (hard stop) |
| `nightly` | — | reporta | advisory (exit 6) | reporta |

- Novo exit `6 = FreshnessAdvisory` (não reservado por POSIX).
- Config: `gate.classes` com overrides por-classe (des/activar sub-exames).

### 7.2. Ficheiros

`cmd/evaluate/evaluate.go` · `pkg/orchestrator/gate.go` · `pkg/exitcodes/exitcodes.go` · `config/config.go` · `action.yml`

---

## 8. L4 — Anti-Regressão de Versão + Referência de Política

### 8.1. Design

- Flags `--release-version` e `--policy-ref` (obrigatórias em modo release-seal) → gravadas na entrada de audit como `release_version`, `policy_ref`. `SealMessage`/`wexstate` **inalterados** (P2).
- Novo `wardex gate check-version --audit-log … --version X`: falha se X já selado; **exit `13 = DuplicateRelease`**.
- Registo de versões = **índice derivado** (`version-registry.json`), mantido no seal, reconstruído da cadeia se stale (P5). A cadeia é a fonte de verdade.
- Action: `release-version` / `policy-ref` requeridos em jobs de release.

### 8.2. Ficheiros

`pkg/orchestrator/gate.go` · `cmd/gate/` (novo) · `pkg/model/audit.go` · `pkg/exitcodes/exitcodes.go` · `action.yml`

### 8.3. Testes

- Segunda selagem da mesma versão → exit 13; registo corrompido → reconstruído da cadeia.

---

## 9. L5 — Streaming + Export SIEM por Cursor

### 9.1. Design

- Novo `pkg/auditlog/reader.go`: iterador streaming (bufio.Scanner, max-bytes por linha), sem carga total do ficheiro — substitui `bytes.Split` em `internal/cpl/chain.go` e o load total em `cmd/audit/verify_chain.go` (P9).
- Novo `wardex audit export --format jsonl|csv --limit N [--cursor <sha256>] [--tail]`:
  - Semântica **LIMIT+1**: devolve N entradas; se existir a N+1, `has_more=true`.
  - `next_cursor` = SHA-256 da última entrada entregue; retoma a partir dela (cross-check com `previous_entry_hash` para integridade na retoma).
  - Sem índice de offsets — o cursor é o próprio hash da cadeia.

### 9.2. Ficheiros

`pkg/auditlog/reader.go` (novo) · `cmd/audit/verify_chain.go` · `cmd/audit/export.go` (novo) · `internal/cpl/chain.go`

### 9.3. Testes

- LIMIT+1 com `has_more`; retoma por cursor em cadeia válida e em tampered (detecta); limite de bytes por linha.

---

## 10. L6 — Envelope Encriptado de Chaves (opt-in)

### 10.1. Decisão (user-approved)

Opt-in com passphrase por flag/env (`--passphrase` ou `WARDEX_KEY_PASSPHRASE`). Default mantém file-perm 0400 para não partir automação/CI.

### 10.2. Design (padrão `store-cipher`)

Envelope JSON versionado:

```
{ "version": 1,
  "kdf": "argon2id", "kdf_salt": hex16B, "kdf_params": {t, m, p},
  "cipher": "aes-256-gcm", "nonce": hex12B,
  "verification_tag": hex32B, "key_type": "ed25519",
  "payload": hex(cifrado) }
```

- Derivação: Argon2id(passphrase, salt, params) → duas saídas: chave de cifra (32B) + chave de verificação (32B) — verificação sem oracle de padding.
- AES-256-GCM sobre o payload canónico (chave privada + metadados); nonce aleatório 12B por envelope.
- `wardex keygen --encrypt`: escreve ficheiro com magic header; `trust`/`provenance` desencriptam in-memory com zeroize após uso.
- Envelope versionado permite migrar KDF/cipher futura sem quebra (P1).

### 10.3. Ficheiros

`pkg/keys/` (novo) · `cmd/keygen/keygen.go` · `pkg/trust/keyring.go` · `pkg/provenance/*`

### 10.4. Testes

- Roundtrip correcto; passphrase errada → erro de verificação (sem oracle); envelope futuro → erro controlado; plaintext legado continua a carregar (P2).

---

## 11. L7 — Kill-Switch com Tripwire (sem dependência Gleipnir)

### 11.1. Decisão (user-approved)

A arquitectura do Wardex **não depende do Gleipnir**. Está pronta quando o Gleipnir amadurecer, mas nunca nesse caminho crítico. O tripwire assenta nas fontes de evidência do próprio Wardex.

### 11.2. Design

- `forced_upgrade` mode: activation por flag ou config selada (`gate.forced_upgrade`), para deadlines regulatórias (CRA Art 14, set/2026).
- Atestação = evidência do próprio Wardex: selo válido, cadeia íntegra, frescura EPSS/KEV.
- **Tripwire (P11):** N falhas consecutivas (default 5, configurável) a refrescar evidência → desarme automático com entrada de audit `forced_upgrade.disarmed`; o gate volta a avaliação por política. Ausência de fonte nunca congela o pipeline para sempre.
- **Gleipnir explícito:** `Anchorer` continua interface opcional pós-evidência (`pkg/provenance/anchorer.go`); ausência de âncora nunca bloqueia. Nenhuma dependência de import nova.

### 11.3. Ficheiros

`pkg/orchestrator/gate.go` · `config/config.go` · `pkg/enrich/*` (contadores de falha) · `pkg/model/audit.go` (eventos `forced_upgrade.{armed,disarmed}`)

### 11.4. Testes

- N falhas → desarme + entrada na cadeia; re-armo após evidência fresca voltar; config sem `forced_upgrade` → comportamento actual inalterado.

---

## 12. Exit Codes Finais

| Código | Semântica | Estado |
|--------|-----------|--------|
| 0 | ALLOW | existente |
| 1 | GenericError | existente |
| 3 | IntegrityFailure | existente |
| 4 | StoreInconsistent | existente |
| 5 | ExpiringSoon | existente |
| **6** | **FreshnessAdvisory** | **novo (L3)** |
| 10 | GateBlocked | existente |
| 11 | ComplianceFail | existente |
| 12 | ActivelyExploited | existente |
| **13** | **DuplicateRelease** | **novo (L4)** |

Sem colisões com códigos reservados POSIX (2, 126, 127).

---

## 13. Compatibilidade e Rollback

- **P0/L1/L2:** retro-compatíveis por construção (P2 — parse de formatos antigos mantido). Rollback = reverter o commit P0; `prev_hash`/leniência v1 continuam aceites.
- **L3/L4/L5/L7:** aditivos; sem flags novas → comportamento actual idêntico.
- **L6:** opt-in; fiches existentes em 0400 plaintext permanecem válidos.
- **Custo de entrada no deficiente:** exits 6 e 13 só ocorrem quando as funcionalidades novas são usadas.

## 14. Riscos

| Risco | Mitigação |
|-------|-----------|
| Alargar `model.AuditEntry` afecta consumidores JSONL externos | Campos `omitempty`; parse leniente; CDDL actualizado |
| `check-version` depende do índice derivado ficar stale | Índice é cache (P5); `check-version` re-constrói se stale; nunca bloqueia por índice ausente — só por evidência na cadeia |
| Envelope de chaves parte automação antiga | Opt-in; detectado por magic header; CI guiada por env var |
| `forced_upgrade` mal configurado | Tripwire por defeito activo (N=5) em lógica de evidência própria; monitorização via entradas de audit |

## 15. Fases de Implementação

- **Fase 0 (fundações):** P0 + L1 + L5-reader.
- **Fase 1 (gate):** L4 (check-version) + L5-export.
- **Fase 2 (keys + classes):** L6 + L3.
- **Fase 3 (versionamento + kill-switch):** L2 + L7.
- **Fase 4 (docs/validação):** README/CHANGELOG/CDDL; `make lint && make test && make security`.

---

## 16. Licença e Atribuição

Os padrões deste documento são transpostos do ecossistema **Nym** (Nym Privacy
Platform) como **referência de desenho**, nunca como cópia literal de código.

- **Upstream:** https://github.com/nymtech/nym — licença **Apache-2.0**
  (`Cargo.toml` → `license = "Apache-2.0"`; `LICENSES/Apache-2.0.txt`).
- **Estado estudado:** snapshot do monorepo `nym-develop`, 2026-09-14 (sem
  metadados git no snapshot local; sem pin de commit).
- **Proveniência:** a atribuição canónica e o mapeamento padrão↔referência
  vivem em `ACKNOWLEDGMENTS.md` (raiz do repo), invocado pelos ficheiros
  PRs/CHANGELOG/README.
- **Compatibilidade:** Apache-2.0 é permissiva e compatível com a incorporação
  em projectos AGPL; por se tratar apenas de padrões de engenharia
  reimplementados em Go, não há obrigações de copyleft sobre esta spec e o
  licenciamento do Wardex (AGPL-3.0-or-later **ou**
  LicenseRef-Wardex-Commercial) mantém-se inalterado.