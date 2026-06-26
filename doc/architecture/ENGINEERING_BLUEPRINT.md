# Wardex — Blueprint de Engenharia

**Versão**: 2.2.0 | **Última actualização**: 2026-06-26 | **Autor**: André Gustavo Leão de Melo Ataíde

---

## Índice

1. [Visão Geral do Sistema](#1-visão-geral-do-sistema)
2. [Stack Tecnológica](#2-stack-tecnológica)
3. [Arquitectura de Alto Nível](#3-arquitectura-de-alto-nível)
4. [Mapa de Responsabilidades dos Packages](#4-mapa-de-responsabilidades-dos-packages)
5. [Fluxos de Dados](#5-fluxos-de-dados)
6. [Modelo de Risco — Equação Formal](#6-modelo-de-risco--equação-formal)
7. [Segurança Criptográfica](#7-segurança-criptográfica)
8. [CLI — Subcomandos e Exit Codes](#8-cli--subcomandos-e-exit-codes)
9. [Configuração e Variáveis de Ambiente](#9-configuração-e-variáveis-de-ambiente)
10. [Arquitectura de Deployment](#10-arquitectura-de-deployment)
11. [Estratégia de Testes](#11-estratégia-de-testes)
12. [Lacunas Identificadas — State Store](#12-lacunas-identificadas--state-store)
13. [Proposta de Solução — Persistent State Store](#13-proposta-de-solução--persistent-state-store)
14. [Referências do Codebase](#14-referências-do-codebase)

---

## 1. Visão Geral do Sistema

**Wardex** é uma ferramenta CLI e biblioteca Go que transforma decisões de segurança e conformidade em evidência auditável. Opera em dois modos independentes:

| Modo | Descrição | Output |
|---|---|---|
| **Compliance Gap Analysis** | Cruza o que as equipas declararam contra o que está operacionalmente confirmado, mapeando ambos contra um catálogo normativo (ISO 27001, SOC 2, NIS 2, DORA, NIST CSF 2.0) | `GapReport` com cobertura, gaps e roadmap |
| **Risk-Based Release Gate** | Avalia cada vulnerabilidade no contexto do asset (criticidade, exposição efectiva, controlos compensatórios), produzindo uma decisão assinada e datada | `GateReport` com ALLOW/WARN/BLOCK |

**Princípio Fundamental**: O Wardex é *stateless* por design — cada execução é independente, sem base de dados, sem estado persistente entre corridas (excepto o snapshot delta e o log de auditoria append-only).

---

## 2. Stack Tecnológica

| Camada | Tecnologia | Justificação |
|---|---|---|
| **Linguagem** | Go 1.26 | stdlib-focused, CGO desactivado, binário estático único |
| **CLI Framework** | Cobra + pflag | Padrão Go para CLIs com subcomandos |
| **Serialização** | yaml.v3 | Formato nativo para configs e evidência GRC |
| **Hashing** | BLAKE3 (lukechampine.com/blake3) | 10-15x mais rápido que SHA-256, 256-bit security |
| **Criptografia** | Ed25519 (stdlib crypto/ed25519) | Trust store, keypairs Admin/CISO/Analyst |
| **Assinatura** | HMAC-SHA256 (stdlib crypto/hmac) | Acceptances, Art14 artefacts, EPSS enrichment |
| **Embebimento** | Go embed | Catálogos de frameworks YAML compilados no binário |
| **Container** | Docker multi-stage | golang:1.26-alpine → distroless/static:nonroot |
| **Orquestração** | Helm v0.1.0 | Kubernetes Job, CronJob, PVC, ConfigMap |
| **CI/CD** | GitHub Actions | ci.yml (test+lint+security), release.yml (GoReleaser) |
| **Release** | GoReleaser | linux/darwin/windows × amd64/arm64, Cosign, CycloneDX SBOM |

**Dependências directas mínimas** (apenas 4):
```
github.com/spf13/cobra
github.com/spf13/pflag
gopkg.in/yaml.v3
lukechampine.com/blake3
```

---

## 3. Arquitectura de Alto Nível

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI Layer (cmd/)                      │
│  evaluate │ assess │ convert │ aggregate │ art14 │ audit     │
│  configseal │ trust │ policy │ simulate │ keygen │ accept   │
├─────────────────────────────────────────────────────────────┤
│                     Core Engine (pkg/)                       │
│  ┌──────────┐ ┌───────────┐ ┌────────────┐ ┌────────────┐  │
│  │ ingestion│ │ correlator│ │  analyzer   │ │   scorer   │  │
│  └────┬─────┘ └─────┬─────┘ └─────┬──────┘ └─────┬──────┘  │
│       │              │             │               │         │
│  ┌────▼──────────────▼─────────────▼───────────────▼──────┐  │
│  │                    releasegate                         │  │
│  │  CalculateRisk() → Evaluate() → GateReport            │  │
│  └────────────────────────┬──────────────────────────────┘  │
│                           │                                 │
│  ┌──────────────┐ ┌───────▼──────┐ ┌───────────┐           │
│  │    accept    │ │    report    │ │ snapshot  │           │
│  │ (HMAC/audit) │ │(md/json/csv) │ │ (delta)   │           │
│  └──────────────┘ └──────────────┘ └───────────┘           │
├─────────────────────────────────────────────────────────────┤
│                   Infrastructure (pkg/)                      │
│  catalog │ model │ trust │ art14 │ epss │ ui │ sdk │ utils  │
├─────────────────────────────────────────────────────────────┤
│                  Internal Packages (internal/)               │
│         cpl (config provenance) │ notification │ policy     │
└─────────────────────────────────────────────────────────────┘
```

**Princípios de Design**:
1. **Stateless processing** — sem base de dados; toda a computação é em memória
2. **Minimal dependencies** — apenas 4 dependências directas
3. **Fail-closed security** — acceptances adulteradas rejeitadas, entradas expiradas bloqueadas
4. **Append-only audit** — logs JSONL com integridade de cadeia
5. **Context-aware risk** — mesmo CVE gera decisões diferentes por contexto de asset
6. **Regulatory hard stops** — Art14 não pode ser ultrapassado por aceitação de risco

---

## 4. Mapa de Responsabilidades dos Packages

### Camada de Dados (`pkg/model/` — 8 ficheiros)

| Tipo | Ficheiro | Responsabilidade |
|---|---|---|
| `ExistingControl`, `CatalogControl`, `Mapping` | control.go | Controlos implementados vs catálogo normativo |
| `Vulnerability`, `AssetContext`, `RiskBreakdown`, `GateReport` | release.go | Vulnerabilidades, contexto de asset, decisão de gate |
| `Finding`, `GapReport`, `ExecutiveSummary`, `Delta` | report.go | Resultados de análise, gaps, executive summary |
| `Acceptance`, `RevocationRecord` | acceptance.go | Aceitações de risco com TTL |
| `AuditEntry` | audit.go | Entradas de auditoria append-only JSONL |
| `Art14NotificationArtefact` | art14.go | Artefactos CRA Article 14 |
| `Asset`, `AssetExposureContext`, `LayerDelta` | asset.go | Assets, exposição, delta paper vs shadow |
| `EPSSEnrichmentFile` | epss.go | Enriquecimento EPSS assinado |

### Camada de Processamento

| Package | Ficheiro-chave | Responsabilidade |
|---|---|---|
| `ingestion` | `ingestion.go` | Load YAML/JSON/CSV, validação de schema, `LoadMany()` com deduplicação |
| `catalog` | `catalog.go` | Catálogos embedded (ISO/SOC2/NIS2/DORA/NIST), parsing com validação estrita |
| `correlator` | `correlator.go` | Mapeamento controlos↔framework: alta confiança (intersecção domínios) + baixa (`strings.Contains`) |
| `analyzer` | `analyzer.go` | `Analyze()` → Finding, `ComputeLayerDelta()` → paper/shadow, `AssessAssets()` → per-asset |
| `scorer` | `scorer.go` | `Score()` → FinalScore, `Summarize()` → ExecutiveSummary, `Roadmap()` → priorização |
| `releasegate` | `gate.go` + `scorer.go` | `CalculateRisk()` → RiskBreakdown, `Evaluate()` → GateReport, `InferMaturityLevel()` |
| `accept` | `accept.go` | HMAC-SHA256 signing, validação business rules, JSONL audit, store consistency |
| `trust` | `types.go` | Ed25519 keypairs, trust store append-only, config sealing (wexstate), RBAC |
| `art14` | (model + generate) | Article 14 lifecycle: Early Warning→Notification→Final Report, HMAC signing |
| `epss` | `epss.go` | Fetch EPSS de FIRST.org, signing, verificação |
| `snapshot` | `snapshot.go` | `.wardex_snapshot.json`, Save/Load/Diff para delta incremental |
| `report` | (generate) | Markdown/JSON/CSV/HTML, stdout ou ficheiro |
| `sdk` | `assess.go` | API programática: `Analyze()`, `LoadControls()`, `Report()` — sem dependência CLI |
| `ui` | (banner/table) | ASCII art, tabelas coloridas (Red/Yellow/Green), ANSI constants |

### Packages Internos

| Package | Responsabilidade |
|---|---|
| `internal/cpl` | Configuration Provenance Link — hashing canónico YAML (SHA-256/BLAKE3), cadeia de auditoria |
| `internal/notification` | Webhook notifications (divergence webhook) |
| `internal/policy` | Gestão de ficheiros de política (validar, listar, adicionar, verificar expiração) |

---

## 5. Fluxos de Dados

### Fluxo A: Compliance Gap Analysis (comando raiz `wardex`)

```
Input Files (YAML/JSON/CSV)
    │
    ▼
┌─────────────────────┐
│ ingestion.LoadMany() │ ──► []ExistingControl
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│   catalog.Load()     │ ──► []CatalogControl (embedded YAML)
└────────┬────────────┘
         │
         ▼
┌──────────────────────┐
│ correlator.Correlate()│ ──► []Mapping (high/low confidence)
└────────┬─────────────┘
         │
         ▼
┌─────────────────────┐
│  analyzer.Analyze()  │ ──► []Finding (covered/partial/gap)
└────────┬────────────┘
         │
    ┌────┴─────────────────┐
    │                      │
    ▼                      ▼
┌──────────────────┐  ┌──────────────────┐
│ ComputeLayerDelta│  │  AssessAssets     │
│ → LayerDelta     │  │ → []AssetCompliance│
└──────────────────┘  └──────────────────┘
         │
         ▼
┌─────────────────────┐
│  scorer.Summarize()  │ ──► ExecutiveSummary
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  snapshot.Diff()     │ ──► Delta (vs previous run)
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  report.Generate()   │ ──► Markdown/JSON/CSV/HTML
└─────────────────────┘
```

### Fluxo B: Release Gate Evaluation (`wardex evaluate`)

```
Vulnerability Evidence (YAML) + wardex-config.yaml
    │
    ▼
┌────────────────────────┐
│ convert grype (optional)│ ──► Wardex YAML format
└────────┬───────────────┘
         │
    ┌────┴──────────────────────┐
    │                           │
    ▼                           ▼
┌──────────────┐  ┌──────────────────┐
│ KEV correlate│  │ accept.Load()     │ ──► Filter accepted CVEs
└──────────────┘  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ epss.Verify()    │ ──► Enrich with signed EPSS
                  └────────┬─────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │ gate.Evaluate(vulns)   │
              │   ┌──────────────────┐ │
              │   │ For each vuln:   │ │
              │   │ CalculateRisk()  │ │
              │   │   = (CVSS/10)    │ │
              │   │   × EPSS × C     │ │
              │   │   × E × (1-Φ)    │ │
              │   │ Compare threshold│ │
              │   │ Decision: a/w/b  │ │
              │   └──────────────────┘ │
              └────────┬───────────────┘
                       │
            ┌──────────┴──────────┐
            │                     │
            ▼                     ▼
   ┌────────────────┐  ┌───────────────────┐
   │ GateReport     │  │ Art14 check       │
   │ ALLOW/WARN/BLOCK│ │ (if exploited)    │
   └───────┬────────┘  └─────────┬─────────┘
           │                     │
           ▼                     ▼
   ┌────────────────┐  ┌───────────────────┐
   │ audit log      │  │ Art14 artefact    │
   │ (JSONL chained)│  │ (HMAC signed)     │
   └───────┬────────┘  └─────────┬─────────┘
           │                     │
           ▼                     ▼
   ┌────────────────┐  ┌───────────────────┐
   │ Forward        │  │ Exit code 12      │
   │ (syslog/ENISA) │  │ (hard stop)       │
   └────────────────┘  └───────────────────┘
```

### Fluxo C: Trust Store & Config Sealing

```
wardex-trust.yaml (Ed25519, append-only)
    │
    ▼
wardex config seal
    │
    ▼
wardex.wexstate (signed config envelope)
    │
    ▼
wardex evaluate --config wardex.wexstate --strict
    │
    ├── Verify seal integrity
    ├── Reject if key revoked
    └── Reject if trust store drifted
```

### Fluxo D: CRA Article 14 Notification Lifecycle

```
Detection (actively_exploited=true)
    │
    ├──► +24h  Early Warning (ENISA/CSIRT)
    │
    ├──► +72h  Notification (detailed)
    │
    └──► +14d  Final Report (post-patch)
```

---

## 6. Modelo de Risco — Equação Formal

O Wardex calcula o risco de release para cada vulnerabilidade no contexto do seu asset:

```
R(v, α) = (CVSS(v)/10) × EPSS(v) × C(α) × E(α) × (1 - Φ(α))
```

| Variável | Descrição | Faixa | Default |
|---|---|---|---|
| `CVSS(v)` | Gravidade intrínseca (NVD) | [0, 10] | — |
| `EPSS(v)` | Probabilidade de exploração em 30d (FIRST.org) | [0, 1] | 1.0 (worst-case) |
| `C(α)` | Criticidade do negócio do asset | [0, 1] | 1.0 |
| `E(α)` | Factor de exposição efectiva | [0, 1] | Calculado |
| `Φ(α)` | Eficácia de controlos compensatórios | [0, 0.8] | 0.0 |

**Exposição efectiva** `E(α)`:
```
E = internetWeight × (1 - authRed) × (1 - reachableRed)

internetWeight = 1.0 (internet-facing) | 0.6 (internal) | 0.3 (development)
authRed        = 0.2 (se requires_auth = true)
reachableRed   = 0.5 (se reachable = false)
```

**Saída normalizada**: `[0, 1.5]` — bandas de decisão:

| Faixa | Decisão | Significado |
|---|---|---|
| `[0, warn_above)` | ALLOW | Risco dentro do apetite |
| `[warn_above, risk_appetite)` | WARN | Risco elevado mas aceitável |
| `[risk_appetite, 1.5]` | BLOCK | Risco inaceitável |

**Modos de avaliação**:
- `any` — Bloqueia se *qualquer* vulnerabilidade exceder o threshold (default)
- `aggregate` — Bloqueia se a *soma* de todos os riscos exceder o threshold

**Maturidade do Gate** (`InferMaturityLevel`): Nível 1-5 baseado na completude do contexto (asset context + compensating controls preenchidos).

---

## 7. Segurança Criptográfica

### 7.1 Aceitação de Risco (HMAC-SHA256)

**Payload canónico**: `"{ID}|{CVE}|{AcceptedBy}|{Justification}|{ExpiresAt_UnixNano}|{Ticket}|{ReportHash}"`

- Chave: 32 bytes (256 bits) via `WARDEX_ACCEPT_SECRET` (nunca em disco)
- Verificação: `subtle.ConstantTimeCompare` (anti timing side-channel)
- Armazenamento: `wardex-acceptances.yaml` (plaintext YAML, segurança pelo HMAC)
- Auditoria: `wardex-accept-audit.log` (JSONL append-only com cadeia)

### 7.2 Configuration Provenance Link (CPL)

- Hash canónico de configuração (chaves ordenadas, sem comentários, whitespace normalizado)
- Algoritmos: SHA-256 ou BLAKE3 (prefixo `sha256:` ou `blake3:`)
- Cadeia de auditoria: cada entrada inclui hash da entrada anterior
- Verificação: `wardex audit verify-link` compara hashes com configs arquivadas

### 7.3 Trust Store (Ed25519)

- Keypairs: Admin, CISO, Analyst (cada um com Ed25519)
- Trust store (`wardex-trust.yaml`): registo append-only com root signature
- Config sealing (`wardex.wexstate`): assinatura Ed25519 do estado da configuração
- RBAC: perfis com thresholds diferentes (ex: Analyst não pode elevar risk_appetite)

### 7.4 CRA Article 14 (HMAC-SHA256)

- Artefactos HMAC signed com o mesmo segredo de aceitação
- Ciclo de vida: draft → dispatched:early-warning → dispatched:notification → dispatched:final-report

### 7.5 EPSS Enrichment (HMAC-SHA256)

- Ficheiros de enriquecimento assinados com HMAC
- Verificação antes de aplicar scores às vulnerabilidades

---

## 8. CLI — Subcomandos e Exit Codes

### 8.1 Subcomandos

| Comando | Propósito | Flags-chave |
|---|---|---|
| `wardex` (raiz) | Compliance gap analysis completo | `--gate`, `--config`, `--output`, `--snapshot` |
| `wardex evaluate` | Release gate focado (CI step) | `--evidence`, `--config`, `--gate-mode`, `--strict` |
| `wardex assess` | Compliance assessment com assets | `--evidence`, `--assets`, `--config` |
| `wardex convert grype` | Grype JSON → Wardex YAML | `--kev`, `--output` |
| `wardex convert sbom` | SBOM → Wardex YAML | `--output` |
| `wardex aggregate` | Combinar múltiplos gate results | `--input`, `--output` |
| `wardex art14` | Article 14 notification lifecycle | `list/show/verify/mark-dispatched/finalize` |
| `wardex audit` | Verificar cadeia de auditoria | `verify-chain`, `verify-link` |
| `wardex config seal` | Selar config em .wexstate | `--output`, `--algorithm` |
| `wardex trust` | Trust store management | `init/add/revoke/list` |
| `wardex policy` | Policy file management | `validate/list/add/check-expiry` |
| `wardex simulate` | Risk simulator HTML | `--output`, `--config` |
| `wardex keygen` | Gerar Ed25519 keypairs | `--name`, `--output-dir` |
| `wardex accept` | Risk acceptance management | `request/list/verify` |
| `wardex enrich epss` | Fetch EPSS scores | `--input`, `--output`, `--sign` |

### 8.2 Exit Codes

| Código | Nome | Significado |
|---|---|---|
| `0` | `OK` | Sucesso / Gate ALLOW |
| `1` | `GenericError` | Erro geral da aplicação |
| `3` | `IntegrityFailure` | HMAC tampering, seal failure, revoked key |
| `4` | `StoreInconsistent` | Acceptance YAML < audit log entries |
| `5` | `ExpiringSoon` | Aproximação da expiração de acceptance |
| `10` | `GateBlocked` | Release gate BLOCK |
| `11` | `ComplianceFail` | Gap score excede --fail-above threshold |
| `12` | `ActivelyExploited` | CRA Article 14 hard stop (não pode ser ultrapassado) |

---

## 9. Configuração e Variáveis de Ambiente

### 9.1 wardex-config.yaml

```yaml
release_gate:
  enabled: true
  risk_appetite: 0.20        # [0, 1.5] threshold para BLOCK
  warn_above: 0.12           # [0, 1.5] threshold para WARN
  mode: any                   # "any" | "aggregate"
  aggregate_limit: 0.50       # threshold para modo aggregate
  asset_context:
    criticality: 0.8
    internet_facing: true
    requires_auth: true
    environment: production
  compensating_controls:
    - type: waf
      effectiveness: 0.3
      justification: "Cloudflare WAF em todos os endpoints"

acceptance:
  hmac_secret_env: WARDEX_ACCEPT_SECRET
  limits:
    max_acceptance_days: 90
    min_justification_chars: 80
    max_report_age_hours: 72
  banned_justification_phrases: ["temporary", "will fix later"]

reporting:
  format: markdown
  gate_log:
    path: wardex-gate-audit.log
    forward: [syslog, enisa]
    on_fail: warn

profiles:
  analyst:
    risk_appetite: 0.15
    warn_above: 0.10
  admin:
    risk_appetite: 0.30
    warn_above: 0.20

cra:
  art14:
    output_dir: .
    awareness_source: detection
    product_name: "My Product"
    kev_path: ./kev-catalogue.json
    kev_max_age_days: 7

notifications:
  divergence_webhook:
    url: https://hooks.slack.com/...
    auth_env: WARDEX_WEBHOOK_SECRET
```

### 9.2 Variáveis de Ambiente

| Variável | Propósito |
|---|---|
| `WARDEX_ACCEPT_SECRET` | HMAC-SHA256 key (min 32 chars) |
| `WARDEX_ACTOR` | Identidade para audit entries (default: `cli`) |
| `WARDEX_SYSLOG_ENDPOINT` | Syslog forwarding target |
| `WARDEX_SYSLOG_PROTO` | Syslog transport (tcp/udp/tls) |
| `WARDEX_SYSLOG_CERT/KEY/CA` | TLS client certs para syslog |

---

## 10. Arquitectura de Deployment

### 10.1 Docker

```dockerfile
# Builder
FROM golang:1.26-alpine AS builder
# CGO disabled, static binary

# Runtime
FROM gcr.io/distroless/static:nonroot
USER 65532:65532
```

### 10.2 Helm Chart (v0.1.0)

Templates:
- `ServiceAccount`, `Secret`, `PVC`
- `Job` (one-shot evaluation)
- `CronJob` (scheduled assessments)
- `ConfigMap` (wardex-config.yaml)

### 10.3 CI/CD Pipeline

```
┌──────────┐     ┌──────────┐     ┌───────────┐     ┌──────────┐
│  ci.yml  │────▶│ docker.yml│────▶│release.yml│────▶│ action.yml│
│test/lint │     │build/push│     │GoReleaser │     │ composite │
│security  │     │ghcr.io   │     │Cosign+SBOM│     │  action   │
└──────────┘     └──────────┘     └───────────┘     └──────────┘
```

### 10.4 GoReleaser Targets

| OS | Arch | Notas |
|---|---|---|
| linux | amd64, arm64 | Primary (Docker + Helm) |
| darwin | amd64, arm64 | macOS (Homebrew) |
| windows | amd64, arm64 | Windows (scoop) |

---

## 11. Estratégia de Testes

| Tipo | Ferramenta | Cobertura | Threshold |
|---|---|---|---|
| Unit Testing | `go test` | Todos os packages core | 40% mínimo (CI enforced) |
| Fuzz Testing | `go test -fuzz` | `pkg/ingestion` | Validção de inputs malformados |
| Security Scan | `govulncheck + gosec` | Todo o código | Block no merge |
| Linting | `golangci-lint v2.11.4` | Todo o código | Block no merge |
| Risk Simulator | `wardex simulate` | Interactive testing | Geração de HTML |

---

## 12. Lacunas Identificadas — State Store

### O Problema

O Wardex é *stateless* por design. Cada execução é independente. No entanto, existem dados que **precisam** de persistir entre execuções para funcionamento correcto:

| Dado | Actual | Impacto da Ausência |
|---|---|---|
| **Snapshot delta** | `.wardex_snapshot.json` (ficheiro avulso) | Sem gerenciamento de lifecycle, sem versionamento, sem partilha |
| **Audit log** | `wardex-gate-audit.log` (JSONL append-only) | Sem query, sem aggregate, sem alertas |
| **Acceptances** | `wardex-acceptances.yaml` + audit log | Dois ficheiros separados, sem transacção atómica |
| **Trust store** | `wardex-trust.yaml` | Append-only mas sem rollback, sem backup automático |
| **Config sealed** | `wardex.wexstate` | Bind estático, sem rotação automática |
| **Gate decisions** | Log apenas | Sem histórico consultável, sem trend analysis |
| **CPL hashes** | Audit log chain | Sem indexação, sem busca por data/config |

### Consequências

1. **Sem continuidade de sessão**: Cada `wardex evaluate` começa do zero — não sabe o que decidiu na execução anterior
2. **Sem trend analysis**: Impossível saber se a postura de segurança está a melhorar ou piorar ao longo do tempo
3. **Sem alertas proactivos**: O sistema não pode notificar quando uma acceptance está para expirar
4. **Sem rollback**: Se uma config selada for comprometida, não há como reverter para um estado anterior
5. **Sem aggregação multi-execução**: Cada execução é um ilha — impossível construir dashboards ou relatórios históricos

---

## 13. Proposta de Solução — Persistent State Store

### 13.1 Princípios de Design

1. **Opt-in**: State store é opcional — sem ele, o Wardex funciona exactamente como hoje
2. **File-based**: Sem base de dados externa — tudo em ficheiros no sistema de ficheiros local
3. **Atomic writes**: Cada operação de escrita é atómica (write-to-temp + rename)
4. **Append-only where possible**: Logs e auditoria mantêm append-only
5. **Portable**: Ficheiros podem ser versionados com git ou partilhados via NFS
6. **Zero dependencies**: Usa apenas stdlib Go (os, filepath, encoding/json, sync)

### 13.2 Estrutura Proposta

```
.wardex/
├── state.json                  # Estado consolidado (singleton)
├── history/
│   ├── 2026-06-26T10:00:00Z.json   # Snapshot de cada execução
│   ├── 2026-06-26T14:30:00Z.json
│   └── ...
├── decisions/
│   ├── 2026-06.json             # Decisões de gate por mês
│   └── ...
├── acceptances/
│   ├── active.yaml              # Acceptances activas
│   ├── audit.jsonl              # Audit log (append-only)
│   └── archive/                 # Acceptances expiradas/revogadas
├── trust/
│   ├── wardex-trust.yaml        # Trust store
│   └── keys/                    # Keypairs (Ed25519)
├── config/
│   ├── wardex.wexstate          # Config selada
│   └── provenance/
│       ├── 2026-06-26.json      # CPL hashes
│       └── ...
└── index.md                     # Auto-generated index (human-readable)
```

### 13.3 Componente `pkg/statestore/`

```go
// pkg/statestore/store.go

package statestore

type Store struct {
    root string // .wardex/ directory
}

type State struct {
    Version       string          `json:"version"`
    LastRun       time.Time       `json:"last_run"`
    LastDecision  string          `json:"last_decision"` // "allow"|"warn"|"block"
    LastRisk      float64         `json:"last_risk"`
    RunCount      int             `json:"run_count"`
    Trend         []TrendPoint    `json:"trend"`         // últimos 30 dias
    ActiveAccepts int             `json:"active_accepts"`
    ExpiringSoon  []string        `json:"expiring_soon"` // CVEs a expirar em 7d
    ConfigHash    string          `json:"config_hash"`
    TrustRootSig  string          `json:"trust_root_sig"`
}

type TrendPoint struct {
    Date      time.Time `json:"date"`
    Risk      float64   `json:"risk"`
    Decision  string    `json:"decision"`
    VulnCount int       `json:"vuln_count"`
}

// New cria ou abre um state store existente
func New(root string) (*Store, error)

// LoadState retorna o estado consolidado actual
func (s *Store) LoadState() (*State, error)

// SaveState grava o estado de forma atómica
func (s *Store) SaveState(state *State) error

// RecordDecision Regista uma decisão de gate no histórico
func (s *Store) RecordDecision(report model.GateReport) error

// History Retorna o histórico de decisões (últimos N dias)
func (s *Store) History(days int) ([]TrendPoint, error)

// TrendAnalysis Analisa a tendência da postura de segurança
func (s *Store) TrendAnalysis() (*TrendAnalysis, error)

// Cleanup Remove snapshots antigos (retention policy)
func (s *Store) Cleanup(retentionDays int) error
```

### 13.4 Integração com o Pipeline Existente

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Evaluate()  │────▶│ GateReport   │────▶│ statestore   │
│  (actual)    │     │ (actual)     │     │ .RecordDecision() │
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │
                                          ┌───────▼───────┐
                                          │ state.json    │
                                          │ (atômico)     │
                                          └───────┬───────┘
                                                  │
                                          ┌───────▼───────┐
                                          │ trend/        │
                                          │ analysis      │
                                          └───────────────┘
```

**Fluxo integrado**:

1. `wardex evaluate` executa como hoje
2. **NOVO**: Após `gate.Evaluate()`, chama `store.RecordDecision(report)`
3. **NOVO**: `state.json` é actualizado atomicamente com último run, tendência, acceptances activas
4. **NOVO**: `--trend` flag mostra tendência últimos 30 dias
5. **NOVO**: `--alert-expiring` flag notifica acceptances a expirar em 7 dias

### 13.5 Compatibilidade

- **Sem state store**: `wardex evaluate` funciona exactamente como hoje (default)
- **Com state store**: `wardex evaluate --state-dir .wardex/` activa persistência
- **Migração**: `wardex state import` importa dados de snapshots/logs existentes
- **Export**: `wardex state export --format json` exporta estado consolidado

### 13.6 Ganhos

| Capabilidade | Antes (stateless) | Depois (com state store) |
|---|---|---|
| Histórico de decisões | Log JSONL sem query | Query por data, CVE, decisão |
| Trend analysis | Impossível | Gráfico de tendência 30/60/90 dias |
| Alertas proactivos | Nenhum | Acceptances a expirar, risco crescente |
| Rollback de config | Impossível | Versões anteriores preservadas |
| Dashboard | Não suportado | `wardex state dashboard` → HTML |
| Multi-execução aggregation | Não | `wardex state aggregate` → relatório |

---

## 14. Referências do Codebase

| Ficheiro | Caminho |
|---|---|
| Entry point | `main.go` |
| Go module | `go.mod` |
| Config loader | `config/config.go` |
| Risk calculation | `pkg/releasegate/scorer.go` |
| Gate engine | `pkg/releasegate/gate.go` |
| Analyzer | `pkg/analyzer/analyzer.go` |
| Correlator | `pkg/correlator/correlator.go` |
| Catalog | `pkg/catalog/catalog.go` |
| Ingestion | `pkg/ingestion/ingestion.go` |
| Exit codes | `pkg/exitcodes/exitcodes.go` |
| Trust types | `pkg/trust/types.go` |
| Acceptance | `pkg/accept/accept.go` |
| Art14 model | `pkg/model/art14.go` |
| SDK | `pkg/sdk/assess.go` |
| Snapshot | `pkg/snapshot/snapshot.go` |
| Technical View | `doc/architecture/TECHNICAL_VIEW.md` |
| Business View | `doc/architecture/BUSINESS_VIEW.md` |
| Crypto Arch | `doc/architecture/CRYPTO_ARCHITECTURE.md` |
| Helm chart | `deploy/helm/wardex/Chart.yaml` |
| CI workflow | `.github/workflows/ci.yml` |
| Dockerfile | `Dockerfile` |
| GoReleaser | `.goreleaser.yaml` |
| GitHub Action | `action.yml` |

---

*Blueprint gerado automaticamente a partir da análise do codebase Wardex v2.2.0.*
