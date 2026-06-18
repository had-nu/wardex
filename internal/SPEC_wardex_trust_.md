# SPEC — Wardex Trust Store & Sealed Config (wexstate)
**Versão:** 1.0.0-draft  
**Autor:** André Ataíde  
**Data:** 2026-05-08  
**Estado:** DRAFT — pendente review  

---

## Problema

O `wardex-config.yaml` é editável por qualquer operador com acesso ao repositório. Um
analista pode alterar `risk_appetite` sem registo, sem assinatura, e sem que o pipeline
detecte a mudança. A cadeia de custódia que o Wardex constrói para vulnerabilidades e
acceptances não existe para a configuração que governa essas decisões.

Esta SPEC especifica:
1. Geração de keypairs por operador (`wardex keygen`)
2. Trust store centralizado (`wardex-trust.yaml`) com bootstrap, adição, e revogação
3. Config selado (`wardex.wexstate`) que o `wardex evaluate` verifica antes de processar
4. Referenciação do trust store central em projectos individuais via `WARDEX_TRUST_STORE`

O Modelo B (servidor centralizado) fica fora de scope e é deixado extensível — ver
secção _Extensibilidade_.

---

## Scope

**In scope**
- `wardex keygen` — gera keypair ed25519 local
- `wardex trust init` — bootstrap do trust store (primeiro uso)
- `wardex trust add` — adiciona actor ao trust store (requer chave admin)
- `wardex trust revoke` — revoga chave existente (requer chave admin)
- `wardex config seal` — sela draft config em `.wexstate` (requer chave com role ciso ou admin)
- Verificação de assinatura no `wardex evaluate` antes de processar
- Enforçamento de permissões do ficheiro da chave privada (modo 400/600)
- `WARDEX_TRUST_STORE` — env var + campo config para trust store remoto/central
- Actualizações de documentação: README e `docs/configuration.md`

**Out of scope**
- Servidor Wardex centralizado (Modelo B) — spec separada
- Interface web de gestão de trust store
- Integração com AD/LDAP/SSO
- Rotação automática de chaves por TTL

---

## Data Model

Pike Regra 5 — structs primeiro.

### `KeyEntry`

```go
// KeyEntry representa uma chave no trust store.
// Cada entrada é imutável após criação — revogação adiciona uma entrada
// em Revocations, não modifica KeyEntry.Status directamente no ficheiro;
// o campo Status é derivado no load.
type KeyEntry struct {
    ID       string    `yaml:"id"`        // formato: <initials>-<role>-<seq>, ex: "km-admin-01"
    PubKey   string    `yaml:"pubkey"`    // "ed25519:<base64>"
    Role     Role      `yaml:"role"`      // admin | ciso | analyst
    Actor    string    `yaml:"actor"`     // email
    Name     string    `yaml:"name"`      // nome completo para audit log
    AddedAt  time.Time `yaml:"added_at"`
    AddedBy  string    `yaml:"added_by"`  // actor email ou "bootstrap"
    AddedSig string    `yaml:"added_sig"` // assinatura ed25519 do entry inteiro por AddedBy
}

// Role define permissões. O Wardex não usa strings — compara Role constants.
type Role string

const (
    RoleAdmin   Role = "admin"
    RoleCISO    Role = "ciso"
    RoleAnalyst Role = "analyst"
)

// RolePermissions define o que cada role pode executar.
// Chave: Role. Valor: set de operações permitidas.
var RolePermissions = map[Role][]Operation{
    RoleAdmin: {
        OpTrustInit, OpTrustAdd, OpTrustRevoke,
        OpConfigSeal, OpEvaluate, OpReport, OpAcceptRequest,
    },
    RoleCISO: {
        OpConfigSeal, OpEvaluate, OpReport, OpAcceptRequest, OpAcceptApprove,
    },
    RoleAnalyst: {
        OpEvaluate, OpReport, OpAcceptRequest,
    },
}

type Operation string

const (
    OpTrustInit      Operation = "trust.init"
    OpTrustAdd       Operation = "trust.add"
    OpTrustRevoke    Operation = "trust.revoke"
    OpConfigSeal     Operation = "config.seal"
    OpEvaluate       Operation = "evaluate"
    OpReport         Operation = "report"
    OpAcceptRequest  Operation = "accept.request"
    OpAcceptApprove  Operation = "accept.approve"
)
```

### `Revocation`

```go
// Revocation é append-only. Nunca modifica KeyEntry.
// O trust store loader marca a KeyEntry como revogada ao encontrar
// uma Revocation com KeyID correspondente.
type Revocation struct {
    KeyID     string    `yaml:"key_id"`
    RevokedAt time.Time `yaml:"revoked_at"`
    RevokedBy string    `yaml:"revoked_by"` // actor email
    Reason    string    `yaml:"reason"`
    Sig       string    `yaml:"sig"` // assinatura ed25519 desta revogação pelo RevokedBy
}
```

### `TrustStore`

```go
// TrustStore é o ficheiro wardex-trust.yaml.
// Nunca é escrito directamente por código — apenas via wardex trust commands.
// O ficheiro inteiro tem uma assinatura de cobertura (RootSig) calculada
// sobre o hash SHA-256 de todos os KeyEntry.AddedSig e Revocation.Sig,
// em ordem de inserção. Qualquer modificação manual invalida RootSig.
type TrustStore struct {
    Version     string       `yaml:"version"`      // "1"
    CreatedAt   time.Time    `yaml:"created_at"`
    CreatedBy   string       `yaml:"created_by"`   // actor email
    Keys        []KeyEntry   `yaml:"keys"`
    Revocations []Revocation `yaml:"revocations"`
    RootSig     string       `yaml:"root_sig"`     // assinatura do admin sobre o estado do store
}
```

### `WexState`

```go
// WexState é o ficheiro wardex.wexstate.
// Payload é o conteúdo do wardex-config.yaml serializado como string YAML.
// O Sig cobre: Version + Payload + SealedAt + SealedBy + TrustStoreRef + TrustStoreSig.
// O evaluate verifica Sig antes de deserializar Payload.
type WexState struct {
    Version       string    `yaml:"version"`         // "1"
    SealedAt      time.Time `yaml:"sealed_at"`
    SealedBy      string    `yaml:"sealed_by"`       // actor email
    SealedByKeyID string    `yaml:"sealed_by_key_id"`// KeyEntry.ID do signatário
    TrustStoreRef string    `yaml:"trust_store_ref"` // URL ou path relativo ao wardex-trust.yaml
    TrustStoreSig string    `yaml:"trust_store_sig"` // SHA-256 do wardex-trust.yaml no momento do seal
    Payload       string    `yaml:"payload"`         // wardex-config.yaml content
    Sig           string    `yaml:"sig"`             // ed25519 signature
}
```

---

## Comandos

### `wardex keygen`

Gera um keypair ed25519. Não tem `--role` — role é atribuído pelo admin no trust store.

```
wardex keygen [flags]

Flags:
  --out string   Path para a chave privada (default: ~/.wardex/keyring.wex)
  -f, --force    Sobrescreve chave existente (requer confirmação explícita)
```

**Comportamento:**
1. Gera keypair via `crypto/ed25519` + `crypto/rand`
2. Escreve chave privada em `--out` com `os.WriteFile(path, data, 0400)` — modo 400 imutável
3. Escreve chave pública em `--out + ".pub"`
4. Imprime path e instrução para enviar `.pub` ao admin

**Output:**
```
Keypair generated.
  Private key : /home/hadnu/.wardex/keyring.wex     (mode 0400 — do not copy)
  Public key  : /home/hadnu/.wardex/keyring.wex.pub (send this to your admin)

This keypair has no role until an admin adds it to the trust store.
```

**Validação de permissões no load (toda operação que usa --keyring):**
```go
// enforceKeyringPermissions rejeita chaves com permissões mais abertas que 0600.
// Igual ao comportamento do openssh.
func enforceKeyringPermissions(path string) error {
    info, err := os.Stat(path)
    if err != nil {
        return fmt.Errorf("keyring: stat %q: %w", path, err)
    }
    mode := info.Mode().Perm()
    if mode > 0600 {
        return fmt.Errorf(
            "keyring: %q has permissions %04o — must be 0400 or 0600\n"+
                "Fix: chmod 400 %s",
            path, mode, path,
        )
    }
    return nil
}
```

---

### `wardex trust init`

Bootstrap. Só funciona se não existir `wardex-trust.yaml` no directório actual.
Não pode ser re-executado — qualquer segundo `trust init` é um erro explícito.

```
wardex trust init [flags]

Flags:
  --keyring string   Path para chave privada do admin (default: ~/.wardex/keyring.wex)
  --actor  string    Email do admin (required)
  --name   string    Nome completo do admin (required)
  --out    string    Path de output (default: ./wardex-trust.yaml)
```

**Comportamento:**
1. Verifica que `./wardex-trust.yaml` não existe — se existir, `exit 1` com mensagem explícita
2. Lê e valida permissões do keyring
3. Cria `TrustStore` com a chave pública do admin, role admin, `added_by: "bootstrap"`
4. Calcula `RootSig` sobre o store
5. Escreve `wardex-trust.yaml`
6. Imprime instruções de branch protection

**Output:**
```
Trust store initialised.
  File    : ./wardex-trust.yaml
  Admin   : carlos.mendes@empresa.pt
  Key ID  : cm-admin-01

NEXT STEPS — do not skip:
  1. git add wardex-trust.yaml
  2. git commit -m "chore: wardex trust bootstrap"
  3. Configure branch protection on this repository:
       - Require pull request reviews before merging
       - Restrict who can push to the default branch
     Without branch protection, this file can be overwritten by any contributor.
```

---

### `wardex trust add`

```
wardex trust add [flags]

Flags:
  --keyring string   Path para chave privada do admin (required)
  --pubkey  string   Path para o .pub do novo actor (required)
  --role    string   Role: analyst | ciso | admin (required)
  --actor   string   Email do novo actor (required)
  --name    string   Nome completo (required)
  --trust   string   Path para wardex-trust.yaml (default: ./wardex-trust.yaml)
```

**Comportamento:**
1. Carrega e verifica `wardex-trust.yaml` — valida `RootSig`
2. Verifica que quem assina tem role `admin`
3. Verifica que `--actor` não existe já no store com status active
4. Gera `KeyEntry.ID` no formato `<iniciais>-<role>-<seq>` — ex: `js-analyst-01`
5. Calcula `AddedSig` sobre o KeyEntry serializado
6. Recalcula `RootSig` sobre o store actualizado
7. Escreve ficheiro actualizado

**Erro se actor já existe:**
```
Error: trust add: joao.silva@empresa.pt already has an active entry (js-analyst-01).
       Use wardex trust revoke to revoke the existing key first.
```

---

### `wardex trust revoke`

```
wardex trust revoke [flags]

Flags:
  --keyring string   Path para chave privada do admin (required)
  --id      string   KeyEntry.ID a revogar (required)
  --reason  string   Motivo da revogação (required, min 10 chars)
  --trust   string   Path para wardex-trust.yaml (default: ./wardex-trust.yaml)
```

**Comportamento:**
1. Adiciona `Revocation` ao store — nunca modifica `KeyEntry`
2. Recalcula `RootSig`
3. Imprime lista de `wardex.wexstate` afectados que precisam de re-seal

**Output:**
```
Key revoked.
  Key ID  : ac-ciso-01
  Actor   : ana.costa@empresa.pt
  Reason  : mudança de função para CPO

WARNING: The following sealed configs reference this key and will be rejected
         by wardex evaluate until re-sealed:
  - ./wardex.wexstate (project: backend-payments)

wardex-trust.yaml updated. Commit and merge via PR.
```

---

### `wardex config seal`

```
wardex config seal [flags]

Flags:
  --keyring string   Path para chave privada (required)
  --input   string   Path para wardex-config.yaml draft (required)
  --out     string   Path de output (default: ./wardex.wexstate)
  --trust   string   Path ou URL para wardex-trust.yaml
                     Sobrepõe WARDEX_TRUST_STORE se definido (default: ./wardex-trust.yaml)
```

**Comportamento:**
1. Resolve trust store: `--trust` > `WARDEX_TRUST_STORE` > `./wardex-trust.yaml`
2. Carrega e verifica trust store — valida `RootSig`
3. Verifica que o keyring corresponde a uma chave active com role `ciso` ou `admin`
4. Lê e valida o draft YAML — campos `PENDING_APPROVAL` causam `exit 1`
5. Calcula SHA-256 do trust store no momento do seal → `TrustStoreSig`
6. Serializa `WexState` e calcula `Sig` ed25519
7. Escreve `.wexstate`

**Erro em campos PENDING:**
```
> **Nota histórica (v1.9.1):** o exemplo abaixo referencia
> `domain_weights.technological` como campo passível de ser marcado
> `PENDING_APPROVAL`. Este campo foi removido do schema em v1.9.1
> (ver `SPEC_v1.9.1_schema_cleanup.md`) por nunca ter sido consumido
> pelo scorer. Para um exemplo equivalente em código vivo, usar
> `release_gate.risk_appetite` ou `acceptance.limits.max_acceptance_days`.

Error: config seal: draft contains unsettled fields:
  - release_gate.risk_appetite: "PENDING_APPROVAL"
  - domain_weights.technological: "PENDING_APPROVAL"

These fields require a decision from the risk owner before sealing.
```

**Erro se role insuficiente:**
```
Error: config seal: key ac-analyst-01 (joao.silva@empresa.pt) has role "analyst".
       Sealing requires role "ciso" or "admin".
```

---

### Verificação no `wardex evaluate`

O `evaluate` verifica o `.wexstate` **antes** de deserializar o payload. Qualquer falha
de integridade é `exit 2` — não `exit 10` (gate block) nem `exit 0`.

```go
// verifySeal verifica a assinatura do wexstate e o estado da chave no trust store.
// Chamado no início de runEvaluate, antes de qualquer acesso ao payload.
func verifySeal(state *WexState, trustStore *TrustStore) error {
    // 1. Verifica que a chave existe no trust store e não está revogada.
    key, err := trustStore.ActiveKey(state.SealedByKeyID)
    if err != nil {
        return fmt.Errorf("seal verification: key %q: %w", state.SealedByKeyID, err)
    }

    // 2. Verifica que o trust store não mudou desde o seal.
    currentSig := sha256sum(trustStore.RawBytes())
    if currentSig != state.TrustStoreSig {
        return fmt.Errorf(
            "seal verification: trust store has changed since seal.\n"+
                "The config must be re-sealed by %s.\n"+
                "Run: wardex config seal --keyring <ciso-keyring> --input wardex-config.yaml",
            key.Actor,
        )
    }

    // 3. Verifica a assinatura ed25519 sobre o payload.
    pubKeyBytes, err := decodeEd25519PubKey(key.PubKey)
    if err != nil {
        return fmt.Errorf("seal verification: decode pubkey: %w", err)
    }
    msg := sealMessage(state) // Version + Payload + SealedAt + SealedBy + TrustStoreRef + TrustStoreSig
    sigBytes, err := base64.StdEncoding.DecodeString(state.Sig)
    if err != nil {
        return fmt.Errorf("seal verification: decode sig: %w", err)
    }
    if !ed25519.Verify(pubKeyBytes, msg, sigBytes) {
        return fmt.Errorf("seal verification: signature invalid — file may have been tampered with")
    }

    return nil
}
```

**Exit codes actualizados:**

| Código | Significado |
|--------|-------------|
| 0      | Gate ALLOW — sem bloqueios |
| 10     | Gate BLOCK — uma ou mais vulns excedem risk_appetite |
| 11     | fail-above excedido |
| 2      | Erro de runtime (I/O, parsing) |
| 3      | Falha de integridade do seal — inclui chave revogada, trust store alterado, assinatura inválida |

---

## Referenciação do Trust Store Central

### Via variável de ambiente (CI)

```bash
# .github/workflows/security-gate.yml
env:
  WARDEX_TRUST_STORE: https://raw.githubusercontent.com/empresa/security-governance/main/wardex-trust.yaml

steps:
  - name: Release gate
    run: wardex evaluate --config wardex.wexstate --evidence vulns.yaml controls.yaml
```

### Via campo no draft config

```yaml
# wardex-config.yaml (draft — antes do seal)
trust_store_ref: "https://raw.githubusercontent.com/empresa/security-governance/main/wardex-trust.yaml"

organization:
  name: "Backend Payments"
  # ...
```

O `wardex config seal` usa este campo se `--trust` não estiver definido e
`WARDEX_TRUST_STORE` não estiver no ambiente.

### Precedência de resolução

```
--trust flag  >  WARDEX_TRUST_STORE env  >  trust_store_ref no config  >  ./wardex-trust.yaml
```

### Fetch do trust store remoto

```go
// fetchTrustStore resolve o trust store por precedência.
// Em ambiente air-gap, WARDEX_TRUST_STORE deve apontar para um path local
// ou para um servidor interno — o Wardex não tem lista de URLs permitidas.
func fetchTrustStore(ref string) ([]byte, error) {
    if strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "http://") {
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()

        req, err := http.NewRequestWithContext(ctx, http.MethodGet, ref, nil)
        if err != nil {
            return nil, fmt.Errorf("trust store: build request: %w", err)
        }
        req.Header.Set("User-Agent", "wardex/"+version.String())

        resp, err := http.DefaultClient.Do(req)
        if err != nil {
            return nil, fmt.Errorf("trust store: fetch %q: %w", ref, err)
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
            return nil, fmt.Errorf("trust store: fetch %q: HTTP %d", ref, resp.StatusCode)
        }

        return io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
    }

    // Path local.
    return os.ReadFile(ref)
}
```

---

## Estrutura de Directórios

```
empresa/security-governance/          ← repositório central
  wardex-trust.yaml                   ← root of trust (branch protection obrigatório)
  wardex-trust.yaml.sig               ← assinatura standalone para verificação offline
  README.md                           ← instruções de onboarding e rotação

empresa/backend-payments/             ← projecto individual
  wardex.wexstate                     ← config selado (committed)
  wardex-config.yaml                  ← draft editável (não committar em produção)
  controls/
    iso27001.yaml
    dora.yaml
  .wardex/
    .gitignore                        ← ignorar keyring.wex (nunca committed)
```

`.wardex/.gitignore`:
```
keyring.wex
```

---

## Exemplos End-to-End

### Bootstrap

```bash
# Gerente de segurança — primeiro uso
wardex keygen --out ~/.wardex/keyring.wex

wardex trust init \
  --keyring ~/.wardex/keyring.wex \
  --actor carlos.mendes@empresa.pt \
  --name "Carlos Mendes" \
  --out ./wardex-trust.yaml

git add wardex-trust.yaml
git commit -m "chore: wardex trust bootstrap — carlos.mendes@empresa.pt"
# Configurar branch protection antes do próximo passo
```

### Onboarding de analista

```bash
# Na máquina do junior
wardex keygen --out ~/.wardex/keyring.wex
# Envia ~/.wardex/keyring.wex.pub ao gerente

# Gerente adiciona
wardex trust add \
  --keyring ~/.wardex/keyring.wex \
  --pubkey /tmp/joao-silva.pub \
  --role analyst \
  --actor joao.silva@empresa.pt \
  --name "João Silva"

git add wardex-trust.yaml
git commit -m "chore: trust add — joao.silva@empresa.pt (analyst)"
# PR → aprovação do admin → merge
```

### Rotação de CISO

```bash
# Revogar CISO anterior
wardex trust revoke \
  --keyring ~/.wardex/keyring.wex \
  --id ac-ciso-01 \
  --reason "mudança de função para CPO"

# Novo CISO gera keypair e envia .pub
# Gerente adiciona
wardex trust add \
  --keyring ~/.wardex/keyring.wex \
  --pubkey /tmp/rui-faria.pub \
  --role ciso \
  --actor rui.faria@empresa.pt \
  --name "Rui Faria"

# Novo CISO re-sela os configs afectados
wardex config seal \
  --keyring ~/.wardex/keyring.wex \
  --input wardex-config.yaml \
  --trust https://raw.githubusercontent.com/empresa/security-governance/main/wardex-trust.yaml \
  --out wardex.wexstate

git add wardex-trust.yaml wardex.wexstate
git commit -m "chore: ciso rotation — rf-ciso-01 replaces ac-ciso-01"
```

### Seal + Evaluate em CI (Go project, GitHub Actions)

```yaml
# .github/workflows/security-gate.yml
name: Wardex Release Gate

on:
  push:
    branches: [main]

env:
  WARDEX_TRUST_STORE: https://raw.githubusercontent.com/empresa/security-governance/main/wardex-trust.yaml

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Wardex
        run: go install github.com/had-nu/wardex@latest

      - name: Run vulnerability scan
        run: grype . -o json > vulns-raw.json

      - name: Convert evidence
        run: wardex convert grype vulns-raw.json > vulns.yaml

      - name: Release gate
        run: |
          wardex evaluate \
            --config wardex.wexstate \
            --evidence vulns.yaml \
            controls/iso27001.yaml controls/dora.yaml
        # exit 0 → ALLOW
        # exit 10 → BLOCK (gate fails the job)
        # exit 3 → integrity failure (seal invalid or key revoked)
```

---

## Ficheiros de Exemplo

### `wardex-trust.yaml` (após bootstrap + onboarding)

```yaml
version: "1"
created_at: "2026-05-08T09:00:00Z"
created_by: "carlos.mendes@empresa.pt"

keys:
  - id: "cm-admin-01"
    pubkey: "ed25519:AAAA...1234"
    role: "admin"
    actor: "carlos.mendes@empresa.pt"
    name: "Carlos Mendes"
    added_at: "2026-05-08T09:00:00Z"
    added_by: "bootstrap"
    added_sig: "ed25519sig:BBBB...5678"

  - id: "rf-ciso-01"
    pubkey: "ed25519:CCCC...9012"
    role: "ciso"
    actor: "rui.faria@empresa.pt"
    name: "Rui Faria"
    added_at: "2026-05-08T15:00:00Z"
    added_by: "carlos.mendes@empresa.pt"
    added_sig: "ed25519sig:DDDD...3456"

  - id: "js-analyst-01"
    pubkey: "ed25519:EEEE...7890"
    role: "analyst"
    actor: "joao.silva@empresa.pt"
    name: "João Silva"
    added_at: "2026-05-08T10:00:00Z"
    added_by: "carlos.mendes@empresa.pt"
    added_sig: "ed25519sig:FFFF...1234"

revocations:
  - key_id: "ac-ciso-01"
    revoked_at: "2026-05-08T14:00:00Z"
    revoked_by: "carlos.mendes@empresa.pt"
    reason: "mudança de função para CPO"
    sig: "ed25519sig:GGGG...5678"

root_sig: "ed25519sig:HHHH...9012"
```

### `wardex.wexstate`

```yaml
version: "1"
sealed_at: "2026-05-08T15:30:00Z"
sealed_by: "rui.faria@empresa.pt"
sealed_by_key_id: "rf-ciso-01"
trust_store_ref: "https://raw.githubusercontent.com/empresa/security-governance/main/wardex-trust.yaml"
trust_store_sig: "sha256:a1b2c3d4e5f6..."
payload: |
  organization:
    name: "Backend Payments"
    sector: "financial_services"
  release_gate:
    enabled: true
    risk_appetite: 0.20
    warn_above: 0.12
  # ... resto do config
sig: "ed25519sig:IIII...3456"
```

---

## Extensibilidade — Modelo B

O Modelo B (servidor centralizado) é suportado pela mesma interface sem alteração de
contrato. O `wardex evaluate` não sabe se `WARDEX_TRUST_STORE` aponta para um raw
GitHub URL ou para `https://wardex.empresa.pt/trust/v1/store`. A função `fetchTrustStore`
é o único ponto de extensão — o servidor devolve o mesmo YAML que o ficheiro estático.

Nenhuma alteração de CLI, structs, ou exit codes é necessária para o Modelo B.

---

## Documentação — Actualizações Obrigatórias

### `README.md`

Adicionar secção **"Trust & Configuration"** após a secção de instalação:

```markdown
## Trust & Configuration

Wardex uses a signed trust store to control who can seal release gate configurations.

**First-time setup (security manager):**
\`\`\`bash
wardex keygen --out ~/.wardex/keyring.wex
wardex trust init --keyring ~/.wardex/keyring.wex --actor you@company.com --name "Your Name"
git add wardex-trust.yaml && git commit -m "chore: wardex trust bootstrap"
\`\`\`

**Onboarding a new operator:**
\`\`\`bash
# Operator generates their keypair and sends the .pub to the admin
wardex keygen --out ~/.wardex/keyring.wex

# Admin adds the operator
wardex trust add --keyring ~/.wardex/keyring.wex --pubkey operator.pub \
  --role analyst --actor operator@company.com --name "Operator Name"
\`\`\`

**Sealing a config (CISO):**
\`\`\`bash
wardex config seal --keyring ~/.wardex/keyring.wex --input wardex-config.yaml --out wardex.wexstate
\`\`\`

For centralized trust stores (multi-project environments), set:
\`\`\`bash
export WARDEX_TRUST_STORE=https://raw.githubusercontent.com/your-org/security-governance/main/wardex-trust.yaml
\`\`\`

See [docs/configuration.md](docs/configuration.md) for the full setup guide.
```

### `docs/configuration.md`

Criar ficheiro com o seguinte conteúdo mínimo (expandir com exemplos desta SPEC):

**Secções obrigatórias:**
1. `## Trust Store` — o que é, onde vive, branch protection
2. `## Keypair Generation` — `wardex keygen`, permissões, o que nunca commitar
3. `## Roles and Permissions` — tabela de roles vs operações
4. `## Sealing a Config` — `wardex config seal`, campos PENDING, o que significa sealed_at
5. `## Referencing a Central Trust Store` — `WARDEX_TRUST_STORE`, precedência de resolução, exemplo GitHub Actions
6. `## Key Rotation` — procedimento de revogação + re-seal
7. `## Air-Gap Environments` — usar path local em vez de URL, mirror do trust store

**Nota sobre o `WARDEX_TRUST_STORE` em projectos Go:**

```markdown
### Referencing the Central Trust Store in a Go Project

Add to your project's `.wardex-config.yaml` draft:

\`\`\`yaml
trust_store_ref: "https://raw.githubusercontent.com/your-org/security-governance/main/wardex-trust.yaml"
\`\`\`

This value is embedded in the `.wexstate` at seal time and used by `wardex evaluate`
to fetch and verify the trust store on each run. In CI, override it with:

\`\`\`bash
export WARDEX_TRUST_STORE=https://raw.githubusercontent.com/your-org/security-governance/main/wardex-trust.yaml
\`\`\`

For Go projects using GitHub Actions, the canonical reference is the raw URL
of `wardex-trust.yaml` on the default branch of your central governance repository,
protected by branch rules. Do not use a URL pointing to a specific commit hash —
revocations would not propagate.
```

---

## Invariants

1. **A chave privada nunca é lida por nenhum subcomando excepto `keygen`, `trust *`, e `config seal`.** O `evaluate` verifica assinaturas com chaves públicas do trust store — nunca com a chave privada.

2. **O trust store é append-only.** `trust revoke` adiciona uma `Revocation` — nunca modifica nem apaga `KeyEntry`. Qualquer `wardex-trust.yaml` com `KeyEntry` em falta (comparado a uma versão anterior) é inválido.

3. **`wardex evaluate` com `.wexstate` cujo signatário está revogado termina em `exit 3`.** Não é tratado como ALLOW nem como BLOCK — é uma falha de integridade, não uma decisão de gate.

4. **Campos `PENDING_APPROVAL` no draft bloqueiam o seal.** O binário não tem lista fixa de campos obrigatórios — qualquer valor igual à string `"PENDING_APPROVAL"` é rejeitado.

5. **O ficheiro da chave privada com permissões > 0600 é rejeitado com erro explícito antes de qualquer operação.**

---

## CI Mirror

```bash
# Gate 1 — qualidade
go vet ./...
staticcheck ./...

# Gate 2 — testes com race detector
go test -race -count=1 ./...

# Gate 3 — segurança
govulncheck ./...
gosec -fmt=json ./... | jq '[.Issues[] | select(.severity == "HIGH" or .severity == "CRITICAL")] | length'
# target: 0

# Gate 4 — smoke
go build -o /tmp/wardex ./cmd/wardex
/tmp/wardex --version
/tmp/wardex keygen --out /tmp/test-keyring.wex
/tmp/wardex trust init --keyring /tmp/test-keyring.wex --actor ci@test.com --name "CI Test" --out /tmp/test-trust.yaml
# exit 0 em ambos

# Gate 5 — permissões
stat -c "%a" /tmp/test-keyring.wex | grep -E "^[46]00$"
# deve ser 400
```
