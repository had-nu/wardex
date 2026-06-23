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

---

Wardex é uma CLI e biblioteca Go que transforma decisões de segurança e conformidade em evidência auditável. Opera em dois modos independentes — nenhum exige o outro.

O release gate avalia cada vulnerabilidade no contexto do ativo que a contém: criticidade do sistema, exposição efectiva, controlos compensatórios já ativos. Em vez de um limiar CVSS estático que bloqueia tudo ou nada, o resultado é uma decisão com registo datado e assinado, que sobrevive a uma auditoria.

A análise de lacunas cruza o que a função de segurança declarou com o que está operacionalmente confirmado, mapeando ambos contra o catálogo do framework escolhido. O resultado não é uma lista de controlos — é a separação entre cobertura genuína, o que existe apenas como política e o que opera fora da governação.

---

## Frameworks suportados

ISO/IEC 27001:2022 · SOC 2 · NIS 2 · DORA · CRA Article 14 · NIST CSF 2.0

```bash
wardex assess controls.yaml --framework iso27001  # predefinição
wardex assess controls.yaml --framework nis2
wardex assess controls.yaml --framework dora
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
docker pull ghcr.io/had-nu/wardex:2.1.2
```

### Helm (Kubernetes)

```bash
helm upgrade --install wardex deploy/helm/wardex/ \
  --set acceptSecret.value=$(openssl rand -hex 32)
```

Consulta [deploy/helm/wardex/](deploy/helm/wardex/) para a referência completa do chart.

---

## Quickstart

Testa o Wardex com os ficheiros de exemplo incluídos no repositório:

```bash
# Converter output do Grype para formato Wardex
wardex convert grype test/usability/grype-results.json > vulns.yaml

# Avaliar com contexto do activo
wardex evaluate \
  --evidence vulns.yaml \
  --config doc/examples/wardex-config.yaml

# Dry-run — pré-visualizar sem escrever artefactos
wardex evaluate --evidence vulns.yaml --config doc/examples/wardex-config.yaml --dry-run

# Exit codes: 0 (ALLOW) · 3 (Adulterado) · 4 (Armazém inconsistente) · 10 (BLOCK) · 11 (Gap) · 12 (Explorado)
```

---

## CRA Article 14 (v2.0)

As obrigações de notificação por exploração activa do Regulamento Europeu de Resiliência Cibernética entram em vigor em setembro de 2026. O Wardex v2.0 implementa o caminho de reporte do Article 14.

### KEV Correlation

```bash
# Descarregar o catálogo CISA KEV
curl -sSL https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o kev-catalogue.json

# Converter output do Grype com correlação KEV
wardex convert grype grype-output.json --kev kev-catalogue.json
```

### Active Exploitation Hard Stop

Quando uma vulnerabilidade é classificada como activamente explorada (`actively_exploited: true`), o `wardex evaluate`:
- Termina com o código **12** (`ActivelyExploited`) — distinto do bloqueio normal de gate (10)
- Gera um artefacto de notificação Article 14 assinado com HMAC-SHA256
- Regista uma entrada de auditoria encadeada com os três prazos CRA
- **Não pode** ser substituído por aceitações de risco

```bash
wardex evaluate --evidence vulns.yaml --config wardex-config.yaml frameworks/iso27001/*.yml
```

### Ciclo de vida do artefacto (`wardex art14`)

```bash
wardex art14 list
wardex art14 show <artefact-id>
wardex art14 verify <artefact-id>
wardex art14 mark-dispatched <artefact-id> --phase early-warning
wardex art14 finalize <artefact-id> --patch-date 2026-06-09T12:00:00Z
```

### Reconhecimento de exploração activa

```bash
wardex accept active-exploit --cve CVE-2024-3094 --justification "..." --art14-artefact wardex-art14-....json
```

**Exit codes (v2.1):** `0` OK · `3` Falha de integridade / Adulterado · `4` Armazém inconsistente · `10` Gate bloqueado · `11` Falha de conformidade · **`12` Activamente explorado**

---
## Análise de gaps de conformidade

O Wardex compara o que o infosec declarou com o que está operacionalmente activo, e identifica o delta em relação ao framework.

### Input

Dois ficheiros YAML com o campo `layer` a identificar a origem:

```yaml
# documented-controls.yaml — políticas declaradas pelo infosec
- id: CTRL-IAM-001
  name: Multi-Factor Authentication
  layer: documented
  domains: [access_control]
  maturity: 4
  evidences:
    - type: policy
      ref: https://wiki.internal/sec/mfa-policy

# implemented-controls.yaml — controlos operacionais confirmados
# (produzido por Bridgr ou mantido manualmente)
- id: CTRL-IAM-001
  name: Multi-Factor Authentication
  layer: implemented
  domains: [access_control]
  maturity: 4
  effectiveness: 0.90
  evidences:
    - type: tool
      ref: okta-mfa-config-2026
```

O mesmo ID em ambos os ficheiros é o caso esperado: controlo declarado e confirmado operacional. IDs presentes apenas num dos ficheiros são o sinal que interessa.

### Execução

```bash
wardex assess documented-controls.yaml implemented-controls.yaml \
  --framework iso27001 \
  -o markdown
```

### O que o report produz

O report separa os resultados em quatro estados de conformidade:

| Categoria | Significado |
|---|---|
| **Coberto** | Presente na camada `implemented`, maturidade >= 3, com evidência operacional. |
| **Política sem execução** | Documentado apenas. Nenhum controlo implementado correspondente. |
| **Prática sem governação** | Implementado mas sem política documentada. |
| **Lacuna** | Ausente em ambas as camadas para um controlo do catálogo. |

A secção `LayerDelta` identifica o desvio real entre a intenção (política) e a execução (código), expondo a ilusão de conformidade.

### Com activos

Se o teu inventário de activos estiver declarado, o report produz uma tabela de conformidade por activo:

```bash
wardex assess documented-controls.yaml implemented-controls.yaml \
  --assets assets.yaml \
  --framework iso27001 \
  -o json --out-file posture.json
```

```yaml
# assets.yaml — v2.0.0 Schema
- id: ASSET-PAY-001
  name: Payment API
  type: application
  criticality: 0.9
  scope: [iso27001]
  controls: [CTRL-IAM-001, CTRL-CRYPTO-002]
  exposure:
    internet_facing: true
    network_zone: dmz
    data_classification: restricted
  threats:
    - id: T-01
      scenario: "API abuse"
      likelihood: high
  owner: platform-team
```

---

## Release gate baseado em risco

O gate avalia cada vulnerabilidade com o modelo:

```
R(v, α) = (CVSS(v)/10) × EPSS(v) × C(α) × E(α) × (1 − Φ(α))
```

`CVSS/10` normaliza o score base para [0, 1]; combinado com `EPSS`, o produto representa severidade ponderada pela probabilidade de exploração activa. `C` é a criticidade do activo, `E` a exposição efectiva, e `Φ` a eficácia dos controlos compensatórios (limitado a 0.80 — um controlo compensatório reduz o risco no máximo 80%). O `R` final situa-se em [0, 1.5]. Os thresholds em `wardex-config.yaml` usam a mesma escala.

O resultado é comparado com o apetite de risco definido em `wardex-config.yaml`. Três bandas possíveis: `ALLOW`, `WARN`, `BLOCK`.

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

O que diferencia o ALLOW do BLOCK não é a CVE — é o contexto do activo. `R` situa-se em [0, 1.5]; cada perfil tem um threshold `risk_appetite` distinto (ver `data/calibration.json`).

| CVE | CVSS | EPSS | [BANK] | [SAAS] | [INFRA] | [HOSP] |
|---|---|---|---|---|---|---|
| Log4Shell | 10.0 | 0.94 | **1.41** `BLOCK` | **0.75** `BLOCK` | **1.41** `BLOCK` | **1.13** `BLOCK` |
| xz backdoor | 10.0 | 0.86 | **1.29** `BLOCK` | **0.69** `BLOCK` | **1.29** `BLOCK` | **1.03** `BLOCK` |
| curl SOCKS5 | 9.8 | 0.26 | **0.38** `BLOCK` | **0.20** `WARN` | **0.38** `BLOCK` | **0.31** `BLOCK` |
| minimist | 9.8 | 0.01 | **0.01** `ALLOW` | **0.01** `ALLOW` | **0.01** `ALLOW` | **0.01** `ALLOW` |

Calibrado contra 237 CVEs reais com EPSS da FIRST.org (`data/dataset_2025-03-01.json`):

| Perfil | Apetite | BLOCK | ALLOW | % Block |
|---|---|---|---|---|
| Banco Tier-1 (DORA) | 0.5 | 176 | 57 | 74% |
| Hospital (HIPAA) | 0.8 | 168 | 63 | 71% |
| Startup SaaS | 2.0 | 111 | 86 | 47% |
| Energia/Águas (NIS2) | 0.3 | 180 | 53 | 76% |

### Enriquecimento EPSS

Quando o scanner não inclui EPSS, o Wardex assume EPSS 1.0 (pior caso) e bloqueia até validação explícita:

```bash
wardex enrich epss wardex-vulns.yaml --output epss-enrich.yaml
wardex evaluate --epss-enrichment epss-enrich.yaml --evidence vulns.yaml controls.yaml
```

O enriquecimento consulta `api.first.org` e assina o resultado via HMAC-SHA256.

### Conversão de formatos

```bash
wardex convert grype results.json > vulns.yaml
wardex convert sbom sbom.xml > vulns.yaml
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
        # Exit 0 = ALLOW, Exit 10 = BLOCK, Exit 11 = compliance gap
```

---

## Ambiente de desenvolvimento

```bash
docker compose up -d         # iniciar PostgreSQL, MinIO e Wardex API stub
docker compose down          # parar tudo
```

O Wardex inclui um [docker-compose.yml](docker-compose.yml) com PostgreSQL (armazém de auditoria), MinIO (bucket de artefactos) e um stub da API Wardex para testes de integração locais. Consulta o ficheiro compose para portas e configuração.

---

## Environment & syslog

O Wardex lê estas variáveis de ambiente no arranque:

| Variável | Predefinição | Descrição |
|---|---|---|
| `WARDEX_ACCEPT_SECRET` | — | Chave HMAC-SHA256 para assinar aceitações e artefactos Art14 (mín 32 car.) |
| `WARDEX_ACTOR` | `cli` | Identidade registada nas entradas de auditoria |
| `WARDEX_SYSLOG_ENDPOINT` | — | `tcp://syslog.example.com:514` — encaminhar eventos para syslog central |
| `WARDEX_SYSLOG_PROTO` | `tcp` | Transporte syslog: `tcp`, `udp`, ou `tls` |
| `WARDEX_SYSLOG_CERT` | — | Caminho para cert TLS cliente para `tls` |
| `WARDEX_SYSLOG_KEY` | — | Caminho para key TLS cliente para `tls` |
| `WARDEX_SYSLOG_CA` | — | Caminho para CA personalizada para `tls` |

O encaminhamento syslog é **opt-in**. Quando `WARDEX_SYSLOG_ENDPOINT` está definido, cada decisão do gate, aceitação e evento do ciclo de vida Art14 é também enviado como mensagem RFC 5424 para o endpoint configurado. A ligação é estabelecida no arranque e restabelecida em caso de falha com backoff exponencial.

---

## Modo PKI

Para ambientes que exigem identidade baseada em certificados em vez de segredos partilhados:

```bash
wardex pki init --org "A Tua Empresa" --validity 3650d
wardex pki issue --name ci-agent --out ci-agent.wex
wardex config seal --keyring ci-agent.wex --input config.yaml --out config.wexstate
```

O modo PKI cria uma CA Ed25519 e emite certificados de operador com validade limitada. Configurações seladas com certificados PKI transportam a cadeia X.509 completa, permitindo verificação automática de expiração sem um trust store externo.

---

## Aceitação de risco

Quando o gate bloqueia e existe um caso de negócio para prosseguir, o Wardex formaliza a excepção com dono nomeado, justificação e TTL. Expirações silenciosas e drift de configuração são detectados automaticamente.

```bash
# Solicitar aceitação
wardex accept request \
  --report report.json \
  --cve CVE-2024-1234 \
  --accepted-by sec-lead@company.com \
  --justification "WAF mitiga o vector de exploração; patch previsto para Q3" \
  --expiry 90d

# Verificar integridade de todas as aceitações activas
wardex accept verify

# Exportar relatório de verificação como artefacto JSON
wardex accept verify --output verification-report.json

# Listar aceitações e estado
wardex accept list --active
```

As aceitações são assinadas com HMAC-SHA256 e registadas em log append-only (JSONL). O Wardex rejeita aceitações expiradas, adulteradas, ou cujo `wardex-config.yaml` sofreu drift desde a assinatura.

---

## Governação: Trust Store & Sealed Config (WexState)

Para conformidade **DORA** e cadeias de custódia não-repudiáveis, o Wardex permite selar as políticas de risco (`wardex-config.yaml`) num envelope criptográfico assinado (`.wexstate`).

- **Identidade forte**: Chaves Ed25519 para Admins, CISOs e Analistas.
- **Sealed config**: As políticas de risco não podem ser alteradas em CI/CD sem aprovação executiva.
- **Trust store append-only**: Registo central de chaves autorizadas e revogações.

```bash
# Sela a política (acção do CISO)
wardex config seal --keyring ciso.wex --input config.yaml --out config.wexstate

# Avalia com verificação obrigatória do selo
wardex evaluate --config config.wexstate --evidence vulns.yaml --strict
```

Consulta o [Playbook de Governação](doc/operations/WARDEX_TRUST_PLAYBOOK.md) para o fluxo completo.

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
- [Playbook — casos de uso com comandos completos](doc/operations/WARDEX_PLAYBOOK.md)
- [Governação — Trust Store & Sealed Config Playbook](doc/operations/WARDEX_TRUST_PLAYBOOK.md)
- [Integração com GitHub Actions](doc/operations/github-actions-integration.md)
- [Helm chart (referência)](deploy/helm/wardex/)
- [Exit codes](doc/operations/EXIT_CODES.md)
- [Ambiente de desenvolvimento (docker-compose)](docker-compose.yml)
- [CHANGELOG](CHANGELOG.md)
- [Contribuir](CONTRIBUTING.md)

---

## Licenciamento

Duplo licenciamento:

**AGPL-3.0 (gratuito):** uso em pipelines CI/CD internas ou em projectos open-source que disponibilizem o código-fonte.

**Licença comercial (pago):** integração em produtos proprietários, plataformas SaaS, ou distribuição sem abertura do código-fonte. Consulta os [Termos Comerciais](doc/governance/COMMERCIAL_LICENSE.md) ou contacta **andre_ataide@proton.me**.
