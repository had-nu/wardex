<h1 align="center">Wardex — The CRA-Ready Release Gate for NIS2 &amp; DORA</h1>

<div align="center">

![Wardex Lockup](pkg/ui/wardex-lockup.svg)

[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/)
[![Go Report Card](https://goreportcard.com/badge/github.com/had-nu/wardex?style=flat-square)](https://goreportcard.com/report/github.com/had-nu/wardex)
[![Coverage](https://img.shields.io/badge/coverage-40%25-yellow?style=flat-square)](#)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io/had--nu/wardex-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/had-nu/wardex/pkgs/container/wardex)
[![Helm](https://img.shields.io/badge/Helm-v0.1.0-0F1689?style=flat-square&logo=helm&logoColor=white)](deploy/helm/wardex/)
[![GitHub Action](https://img.shields.io/badge/GitHub_Action-Wardex_Release_Gate-4A154B?style=flat-square&logo=githubactions&logoColor=white)](https://github.com/marketplace/actions/wardex-release-gate)
[![License: AGPL v3 / Commercial](https://img.shields.io/badge/License-AGPL_v3_|_Commercial-8A2BE2.svg?style=flat-square)](#licenciamento)

<br>
<a href="README-en.md">English</a> | <a href="README.md">Português</a>
<br><br>

</div>

> [!IMPORTANT]
> **CRA Article 14 (v2.0):** As obrigações de notificação por exploração activa do Cyber Resilience Act entram em vigor em setembro de 2026. O Wardex v2.0 implementa o caminho completo: correlação com o catálogo CISA KEV, exit code distinto (`12`), artefacto de notificação assinado com HMAC-SHA256, e registo de auditoria encadeado com os três prazos regulatórios. Este caminho não pode ser substituído por aceitações de risco.
>
> **EU AI Act (v2.4.0):** O Regulamento da Inteligência Artificial (UE 2024/1689) já está disponível como framework de controlos. 31 controlos catalogados cobrindo todos os artigos-chave: práticas proibidas, gestão de riscos, governação de dados, transparência, supervisão humana, exatidão/solidez/cibersegurança, obrigações de prestadores e implantadores, GPAI, acompanhamento pós-comercialização e comunicação de incidentes. Usa `--framework eu_ai_act` para avaliar a conformidade.

---

Wardex é uma CLI e biblioteca Go que transforma decisões de segurança e conformidade em evidência auditável. Opera em dois modos independentes — nenhum exige o outro.

**Posicionamento europeu:** O Wardex é construído de raiz para os regulamentos europeus — NIS2, DORA, CRA, **EU AI Act** — e para o padrão de compliance que está a emergir na UE. Cada decisão do release gate, cada aceitação de risco, cada artefacto Art14 é selado criptograficamente e registado num audit log encadeado que sobrevive a auditorias externas.

---

## Audit Log Encadeado — Feature Principal

O audit log encadeado é o coração do Wardex. Cada entrada é ligada criptograficamente à anterior, formando uma cadeia inviolável de evidência.

```
┌─────────────┐    SHA-256    ┌─────────────┐    SHA-256    ┌─────────────┐
│  Entrada 1  │──────────────▶│  Entrada 2  │──────────────▶│  Entrada 3  │
│  (genesis)  │               │  (decisão)  │               │  (aceitação)│
└─────────────┘               └─────────────┘               └─────────────┘
       │                             │                             │
       ▼                             ▼                             ▼
  Config hash                 Config hash                   Config hash
  (CPL v2.2)                  (CPL v2.2)                   (CPL v2.2)
```

**O que torna inviolável:**
- Cada entrada inclui o hash da entrada anterior (hash encadeado)
- O hash da configuração (CPL) liga cada decisão à política em vigor
- Alterações ao audit log ou à configuração são detectadas imediatamente
- Exportável como JSONL para SIEM, Datadog, ou auditoria externa

```bash
# Verificar integridade da cadeia
wardex audit verify-chain --audit-log wardex-gate-audit.log

# Verificar ligação com configurações arquivadas
wardex audit verify-link --audit-log wardex-gate-audit.log --config-archive ./configs/
```

---

## What's New — v2.3.0 / v2.4.0

**CBOR Deterministic Canonicalization (v2.3.0):**
- Toda a canonicalização para assinatura migrou de formatos ad-hoc para CBOR
  Core Deterministic Encoding (RFC 8949 §4.2.3) via `fxamacker/cbor/v2`
- CPL config hash, WexState seal message, e tool attestation usam o mesmo
  mecanismo determinístico, garantindo byte-identicidade entre plataformas

**CDDL Schemas (v2.3.0):**
- `spec/cddl/` define formalmente CPL audit entries, WexState envelopes,
  e 3CP tool attestations em CDDL (RFC 8610)
- Servem como fonte da verdade para serialização e confluência entre
  implementações

**3CP Tool Provenance Attestation (v2.3.0):**
- `pkg/attest/` — atestação Ed25519 + CBOR determinístico para provenance
  de ferramentas (grype, sbom, kev)
- Interface `Anchorer` abstrai o backend 3CP (Gleipnir embedded, gRPC, noop)
- `--attest` flag nos converters + `wardex provenance attest` CLI

**EU AI Act Framework (v2.4.0):**
- Catálogo completo do Regulamento (UE) 2024/1689: práticas proibidas, gestão de riscos, governação de dados, documentação técnica, transparência, supervisão humana, exatidão/solidez/cibersegurança, obrigações de prestadores e implantadores, avaliação de impacto sobre direitos fundamentais, GPAI, acompanhamento pós-comercialização, comunicação de incidentes
- Usar: `wardex --framework eu_ai_act ./frameworks/eu_ai_act/*.yml`

**Gleipnir Provenance Anchoring:**
- Prova de integridade imutável para artefactos de release via `wardex provenance seal`
- Suporte a embedded consensus engine (gleipnir-embedded) ou servidor gRPC remoto
- Chain seal com SHA-256 de todos os artefactos + âncora criptográfica

**Isolamento do driver gRPC:**
- O driver de proveniência gRPC (com protobuf) foi isolado atrás da build tag `grpc` para evitar panic ao init. Para usar: `go build -tags grpc`.

---

## Frameworks suportados

ISO/IEC 27001:2022 · SOC 2 · NIS 2 · DORA · CRA Article 14 · NIST CSF 2.0 · **EU AI Act**

```bash
wardex assess controls.yaml --framework iso27001     # predefinição
wardex assess controls.yaml --framework nis2
wardex assess controls.yaml --framework dora
wardex assess controls.yaml --framework eu_ai_act    # novo v2.4.0
```

---

## Instalação

```bash
go install github.com/had-nu/wardex/v2@latest
```

Requer Go ≥ 1.26. Confirma que `$(go env GOPATH)/bin` está no teu `$PATH`.

Para compilar a partir do código-fonte:

```bash
git clone https://github.com/had-nu/wardex.git
cd wardex && make build
```

### Docker

```bash
docker pull ghcr.io/had-nu/wardex:2.2.2
```

### Helm (Kubernetes)

```bash
helm upgrade --install wardex deploy/helm/wardex/ \
  --set acceptSecret.value=$(openssl rand -hex 32)
```

Consulta [deploy/helm/wardex/](deploy/helm/wardex/) para a referência completa do chart.

---

## Quickstart

### 1. Avaliar risco de vulnerabilidades

```bash
# Converter output do Grype para formato Wardex
wardex convert grype test/usability/grype-results.json > vulns.yaml

# Avaliar com contexto do activo
wardex evaluate \
  --evidence vulns.yaml \
  --config doc/examples/wardex-config.yaml

# Dry-run — pré-visualizar sem escrever artefactos
wardex evaluate --evidence vulns.yaml --config doc/examples/wardex-config.yaml --dry-run
```

### 2. Gerar e gerir chaves

```bash
# Gerar chave Ed25519 para o sistema de confiança
wardex keygen

# A chave é criada em ~/.crypto/trust/root.key
# A pública é ~/.crypto/trust/root.key.pub (enviar ao admin)
```

### 3. Selar e verificar provenance

```bash
# Selar diretório de artefactos com Gleipnir (v2.4.0+)
wardex provenance seal \
  --dir ./dist \
  --output chain-seal.json \
  --label "release-v2.4.0"

# Verificar integridade
wardex provenance verify <chain-hash>
```

**Exit codes:** `0` ALLOW · `3` Adulterado · `4` Armazém inconsistente · `10` BLOCK · `11` Gap · `12` Explorado activamente

---

## Comandos Principais

| Comando | Descrição |
|---------|-----------|
| `wardex evaluate` | Avalia vulnerabilidades contra o release gate |
| `wardex assess` | Análise de lacunas de conformidade |
| `wardex convert grype/sbom` | Converte output de scanners para formato Wardex |
| `wardex enrich epss` | Enriquece vulnerabilidades com dados EPSS |
| `wardex accept request/verify/list` | Gestão de aceitações de risco |
| `wardex art14 list/show/verify` | Ciclo de vida do artefacto CRA Article 14 |
| `wardex provenance seal/submit/attest/verify/status` | Proveniência criptográfica 3CP com Gleipnir |
| `wardex config hash/seal` | CPL e sealed config (CBOR determinístico v2.3.0+) |
| `wardex audit verify-chain/verify-link` | Verificação do audit log encadeado |
| `wardex trust init/add` | Gestão do trust store |
| `wardex keygen` | Geração de chaves Ed25519 |
| `wardex pki init/issue` | Modo PKI com CA Ed25519 |
| `wardex policy show` | Mostra política de risco configurada |
| `wardex simulate` | Simula decisões do gate com dados históricos |

---

## Release Gate Baseado em Risco

### Configuração

```yaml
# wardex-config.yaml
release_gate:
  enabled: true
  risk_appetite: 0.20
  warn_above: 0.12
  mode: any               # "any" bloqueia se qualquer vuln exceder; "aggregate" usa soma
  asset_context:
    criticality: 0.8
    internet_facing: true
    requires_auth: true
  compensating_controls:
    - type: waf
      effectiveness: 0.35
```

### A mesma CVE, quatro contextos

| CVE | CVSS | EPSS | [BANK] | [SAAS] | [INFRA] | [HOSP] |
|---|---|---|---|---|---|---|
| Log4Shell | 10.0 | 0.94 | **1.41** `BLOCK` | **0.75** `BLOCK` | **1.41** `BLOCK` | **1.13** `BLOCK` |
| xz backdoor | 10.0 | 0.86 | **1.29** `BLOCK` | **0.69** `BLOCK` | **1.29** `BLOCK` | **1.03** `BLOCK` |
| curl SOCKS5 | 9.8 | 0.26 | **0.38** `BLOCK` | **0.20** `WARN` | **0.38** `BLOCK` | **0.31** `BLOCK` |
| minimist | 9.8 | 0.01 | **0.01** `ALLOW` | **0.01** `ALLOW` | **0.01** `ALLOW` | **0.01** `ALLOW` |

### Enriquecimento EPSS

```bash
wardex enrich epss wardex-vulns.yaml --output epss-enrich.yaml
wardex evaluate --epss-enrichment epss-enrich.yaml --evidence vulns.yaml controls.yaml
```

### Integração CI/CD

```yaml
# .github/workflows/wardex-gate.yml
jobs:
  risk-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Wardex
        run: go install github.com/had-nu/wardex/v2@latest
      - name: Evaluate risk gate
        run: |
          wardex evaluate \
            --config .wardex/config.yaml \
            --evidence vulns.yaml \
            controls.yaml
```

---

## Análise de Gaps de Conformidade

O Wardex compara o que o infosec declarou com o que está operacionalmente activo, e identifica o delta em relação ao framework.

| Categoria | Significado |
|---|---|
| **Coberto** | Presente na camada `implemented`, maturidade >= 3, com evidência operacional. |
| **Política sem execução** | Documentado apenas. Nenhum controlo implementado correspondente. |
| **Prática sem governação** | Implementado mas sem política documentada. |
| **Lacuna** | Ausente em ambas as camadas para um controlo do catálogo. |

```bash
wardex assess documented-controls.yaml implemented-controls.yaml \
  --framework iso27001 \
  -o markdown

# Com inventário de activos
wardex assess documented-controls.yaml implemented-controls.yaml \
  --assets assets.yaml \
  --framework iso27001 \
  -o json --out-file posture.json
```

---

## CRA Article 14

As obrigações de notificação por exploração activa do Regulamento Europeu de Resiliência Cibernética entram em vigor em setembro de 2026.

**Active Exploitation Hard Stop:** Quando uma vulnerabilidade é classificada como activamente explorada (`actively_exploited: true`), o `wardex evaluate` termina com código **12** — distinto do bloqueio normal (10). Não pode ser substituído por aceitações de risco.

```bash
# Artefacto Art14
wardex art14 list
wardex art14 show <artefact-id>
wardex art14 verify <artefact-id>
wardex art14 mark-dispatched <artefact-id> --phase early-warning

# Aceitação de exploit activo
wardex accept active-exploit --cve CVE-2024-3094 --justification "..." --art14-artefact wardex-art14-....json
```

Consulta o [Playbook de Governação](doc/operations/WARDEX_TRUST_PLAYBOOK.md) para o fluxo completo.

---

## EU AI Act (Regulamento da Inteligência Artificial)

O Regulamento (UE) 2024/1689 — EU AI Act — está disponível como framework de controlos no Wardex v2.4.0. São 31 controlos catalogados que cobrem todas as obrigações aplicáveis a sistemas de IA de risco elevado, modelos de IA de finalidade geral (GPAI) e práticas proibidas.

### Controlos por domínio

| Domínio | Controlos | Artigos |
|---|---|---|
| Prohibited practices | 1 | Art 5 |
| Governance & classification | 4 | Arts 6, 21, 49, 99 |
| Risk management | 1 | Art 9 |
| Data governance | 1 | Art 10 |
| Documentation & records | 4 | Arts 11, 12, 18, 19 |
| Transparency | 2 | Arts 13, 50 |
| Human oversight | 1 | Art 14 |
| Technical (accuracy, robustness, security) | 2 | Arts 15, 19 |
| Provider obligations | 2 | Arts 16, 20 |
| Quality management | 1 | Art 17 |
| Deployer obligations | 2 | Arts 26, 27 |
| Value chain (importer, distributor, rep) | 4 | Arts 22, 23, 24, 25 |
| Conformity assessment | 2 | Arts 43, 47 |
| GPAI (general-purpose AI) | 2 | Arts 53, 55 |
| Post-market & incident reporting | 2 | Arts 72, 73 |

```bash
# Avaliar conformidade com EU AI Act
wardex --framework eu_ai_act ./frameworks/eu_ai_act/*.yml

# Listar controlos do catálogo
wardex --framework eu_ai_act --output json ./frameworks/eu_ai_act/*.yml
```

### Proveniência 3CP com Gleipnir

Cada release pode ser selado criptograficamente com o Gleipnir embedded consensus engine.
O Wardex abstrai o backend 3CP através da interface `Anchorer` — Gleipnir é a referência,
mas qualquer motor 3CP compatível funciona.

```bash
# Selar artefactos de release
wardex provenance seal \
  --dir ./dist \
  --output chain-seal.json \
  --label "wardex-v2.4.0-eu-ai-act"

# Ancorar commit de tag
wardex provenance submit $(git rev-parse v2.4.0) --label "git-tag-v2.4.0"

# Atestar provenance de ferramenta (v2.3.0+)
wardex provenance attest input.txt --tool my-scanner --version 1.0 --sign-key key.wex

# Converter e atestar num passo
wardex convert grype grype-output.json --attest key.wex

# Verificar estado da cadeia
wardex provenance status
```

---

## Gestão de Chaves & Governação

### Chaves Criptográficas

Todas as chaves Ed25519 são armazenadas em `~/.crypto/` com subdiretórios por finalidade:

```
~/.crypto/
├── provenance/          # Assinatura de manifestos de provenance + atestações 3CP
│   ├── signing.key      # Ed25519 privada (mode 0400)
│   └── signing.key.pub  # Ed25519 pública
└── trust/               # Sistema de confiança wardex
    └── root.key         # Chave raiz (gerada por wardex keygen)
```

**Permissões**: Directórios `700`, chaves privadas `0400`, chaves públicas `0644`.

### Verificação de Provenance

Para releases recentes (v2.3.0+), usar o Gleipnir embedded com CBOR deterministic attestation:

```bash
# Verificar chain seal de release
wardex provenance verify <chain-hash>

# Verificar estado da cadeia
wardex provenance status

# Verificar atestação de ferramenta
# (o .attest é CBOR determinístico, verificável com qualquer implementação 3CP)
```

Para releases anteriores (v2.2.2), a chave pública abaixo permite verificar o manifesto de proveniência:

> **Chave pública de assinatura (v2.2.2):**
> ```
> ed25519:HsD9e6BB2LlaeKODGqgWUZoflDgdUH1HWTdyWA7dGqE=
> ```

> **Root hash (BLAKE3, 113 ficheiros):**
> ```
> sha256:6f972edf99f5457f8fb13668c529f4343dab7a76d20b67ea746ebdf54d910fee
> ```

### Trust Store & Sealed Config (WexState)

Para conformidade **DORA** e cadeias de custódia não-repudiáveis:

- **Identidade forte**: Chaves Ed25519 para Admins, CISOs e Analistas.
- **Sealed config**: As políticas de risco não podem ser alteradas sem aprovação executiva.
- **Trust store append-only**: Registo central de chaves autorizadas e revogações.

```bash
# Sela a política (acção do CISO)
wardex config seal --keyring ~/.crypto/trust/root.key --input config.yaml --out config.wexstate

# Avalia com verificação obrigatória do selo
wardex evaluate --config config.wexstate --evidence vulns.yaml --strict
```

### Modo PKI

Para ambientes que exigem identidade baseada em certificados:

```bash
wardex pki init --org "A Tua Empresa" --validity 3650d
wardex pki issue --name ci-agent --out ci-agent.wex
wardex config seal --keyring ci-agent.wex --input config.yaml --out config.wexstate
```

---

## Environment & Syslog

| Variável | Predefinição | Descrição |
|---|---|---|
| `WARDEX_ACCEPT_SECRET` | — | Chave HMAC-SHA256 para assinar aceitações e artefactos Art14 (mín 32 car.) |
| `WARDEX_ACTOR` | `cli` | Identidade registada nas entradas de auditoria |
| `WARDEX_SYSLOG_ENDPOINT` | — | `tcp://syslog.example.com:514` — encaminhar eventos para syslog central |
| `WARDEX_SYSLOG_PROTO` | `tcp` | Transporte syslog: `tcp`, `udp`, ou `tls` |
| `WARDEX_SYSLOG_CERT` | — | Caminho para cert TLS cliente para `tls` |
| `WARDEX_SYSLOG_KEY` | — | Caminho para key TLS cliente para `tls` |
| `WARDEX_SYSLOG_CA` | — | Caminho para CA personalizada para `tls` |

---

## SDK

```go
import "github.com/had-nu/wardex/v2/pkg/sdk"

controls, _ := sdk.LoadControls("./controls.yaml")
result, _   := sdk.Analyze(controls, "iso27001")

fmt.Printf("Coverage: %.1f%%\n", result.Summary.GlobalCoverage)
```

Para o release gate:

```go
import (
    "github.com/had-nu/wardex/v2/pkg/model"
    "github.com/had-nu/wardex/v2/pkg/releasegate"
)

gate := releasegate.Gate{
    AssetContext: model.AssetContext{
        Criticality:    0.9,
        InternetFacing: true,
        RequiresAuth:   true,
    },
    CompensatingControls: []model.CompensatingControl{
        {Type: "waf", Effectiveness: 0.35},
    },
    RiskAppetite: 0.20,
}

report := gate.Evaluate([]model.Vulnerability{
    {CVEID: "CVE-2024-1234", CVSSBase: 9.1, EPSSScore: 0.84, Reachable: true},
})

fmt.Println(report.OverallDecision) // ALLOW | WARN | BLOCK
```

---

## Documentação

- [Arquitectura e funcionamento interno](doc/architecture/TECHNICAL_VIEW.md)
- [Contexto de negócio e o problema do gate binário](doc/architecture/BUSINESS_VIEW.md)
- [Arquitectura Criptográfica (CBOR, CDDL, 3CP)](doc/architecture/CRYPTO_ARCHITECTURE.md)
- [REC + Provenance — Plano de Mitigação](doc/architecture/REC_PROVENANCE_ENHANCEMENT.md)
- [Playbook — casos de uso com comandos completos](doc/operations/WARDEX_PLAYBOOK.md)
- [Governação — Trust Store & Sealed Config Playbook](doc/operations/WARDEX_TRUST_PLAYBOOK.md)
- [Integração com GitHub Actions](doc/operations/github-actions-integration.md)
- [Helm chart (referência)](deploy/helm/wardex/)
- [Exit codes](doc/operations/EXIT_CODES.md)
- [Migração CBOR v2.3.0](internal/doc/CBOR_MIGRATION_v2.3.0.md)
- [Esquemas CDDL](spec/cddl/)
- [Ambiente de desenvolvimento (docker-compose)](docker-compose.yml)
- [CHANGELOG](CHANGELOG.md)
- [Contribuir](CONTRIBUTING.md)

---

## Licenciamento

Duplo licenciamento:

**AGPL-3.0 (gratuito):** uso em pipelines CI/CD internas ou em projectos open-source que disponibilizem o código-fonte.

**Licença comercial (pago):** integração em produtos proprietários, plataformas SaaS, ou distribuição sem abertura do código-fonte. Consulta os [Termos Comerciais](doc/governance/COMMERCIAL_LICENSE.md) ou contacta **andre_ataide@proton.me**.
