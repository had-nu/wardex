# Wardex Playbook v2.1

Guia operacional para release gates baseados em risco, análise de gaps de conformidade, e notificação CRA Article 14.

**Versão:** v2.1.0 · **Público:** DevSecOps, CISOs, Compliance Engineers, Platform Teams

---

## Índice

1. [Quick Start](#1-quick-start)
2. [Framework Use Cases](#2-framework-use-cases)
3. [Compliance Gap Analysis](#3-compliance-gap-analysis)
4. [Risk-Based Release Gate](#4-risk-based-release-gate)
5. [CRA Article 14 — Active Exploitation](#5-cra-article-14--active-exploitation)
6. [EPSS Enrichment](#6-epss-enrichment)
7. [Risk Acceptance & Audit Chain](#7-risk-acceptance--audit-chain)
8. [Governance: Trust Store & Sealed Config](#8-governance-trust-store--sealed-config)
9. [CI/CD Integration](#9-cicd-integration)
10. [Exit Codes Reference](#10-exit-codes-reference)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Quick Start

```bash
# Instalar (SHA-pinned)
go install github.com/had-nu/wardex@95eed886

# Converter output do Grype
wardex convert grype grype-results.json > vulns.yaml

# Avaliar com contexto de activo
wardex evaluate \
  --evidence vulns.yaml \
  --config wardex-config.yaml

# Analisar gaps de conformidade
wardex assess documented.yaml implemented.yaml \
  --framework iso27001 \
  -o markdown
```

---

## 2. Framework Use Cases

Casos de uso organizados por framework regulatório. Cada framework tem duas perspectivas: técnica (o engenheiro executa) e de negócio (o decisor avalia).

---

### DORA — Digital Operational Resilience Test

**Caso técnico: selar política de risco para aprovação executiva**

O CISO define o `risk_appetite`, gera o key pair, sela a configuração, e a equipa de plataforma só consegue alterar o ficheiro `.wexstate` com aprovação do CISO:

```bash
# CISO gera identidade
wardex keygen --keyring ciso.wex
wardex trust add --keyring ciso.wex --role admin

# CISO sela a política
wardex config seal \
  --keyring ciso.wex \
  --input wardex-config.yaml \
  --out config.wexstate

# Pipeline corre com selo verificado
wardex evaluate \
  --config config.wexstate \
  --evidence vulns.yaml \
  --strict
```

**Caso de negócio: auditoria de terceiros (ICT third-party risk)**

O regulador DORA exige que operadores críticos mapeiem e auditem controlos de terceiros. Com o Wardex, documentas os controlos do teu SaaS provider como `documented` e os teus controlos internos como `implemented`. O `LayerDelta` mostra o que o terceiro diz que faz vs o que conseguiste verificar:

```bash
wardex assess saas-provider-documented.yaml internal-implemented.yaml \
  --framework dora \
  -o markdown \
  --out-file third-party-audit.md
```

O report produz evidência para o regulador de que existe um processo de verificação de controlos de terceiros — e onde o terceiro está a operar fora da tua governação.

---

### NIS2 — Network and Information Systems

**Caso técnico: release gate para operador de serviços essenciais**

Um operador de energia (NIS2 essential entity) corre o gate em cada deploy de sistema SCADA. O `risk_appetite` é 0.3 — o mais baixo do portefólio. Cada deploy é avaliado com contexto de activo (internet-facing, criticality 0.9, sem controlos compensatórios):

```bash
wardex evaluate \
  --evidence scada-vulns.yaml \
  --config nis2-essential-config.yaml
```

Se alguma vulnerabilidade excede, o pipeline bloqueia com exit 10. A aceitação de risco só é possível com assinatura do responsável de segurança e prazo de validade:

```bash
wardex accept request \
  --report report.json \
  --cve CVE-2024-5678 \
  --accepted-by ciso@energia.pt \
  --justification "Sistema isolado em rede OT; patch na janela de manutenção de Julho" \
  --expiry 30d
```

**Caso de negócio: report de postura para o board**

O CISO precisa de apresentar ao conselho de administração a evolução trimestral da postura de segurança. Com snapshots, o Wardex mostra a diferença entre trimestres:

```bash
wardex assess Q1-documented.yaml Q1-implemented.yaml \
  --assets assets.yaml \
  --framework nis2 \
  -o json --out-file Q1-posture.json

wardex assess Q2-documented.yaml Q2-implemented.yaml \
  --assets assets.yaml \
  --framework nis2 \
  -o json --out-file Q2-posture.json
```

O board vê: "Cobertura de controlos subiu de 62% para 71%", "Paper security reduziu de 18% para 11%", e "3 activos críticos saíram de shadow security". Não são métricas de vaidade — é o LayerDelta que o NIS2 exige.

---

### CRA — Cyber Resilience Act

**Caso técnico: pipeline de notificação Article 14**

Um fabricante de software incorpora o gate no CI/CD para detectar exploração activa antes de cada release. Quando uma CVE está no catálogo CISA KEV, o pipeline falha com exit 12 e gera automaticamente o artefacto de notificação:

```bash
# CI step: correlacionar com KEV
wardex convert grype grype-output.json --kev kev-catalogue.json

# CI step: avaliar e gerar artefacto
wardex evaluate --evidence vulns.yaml --config config.yaml

# Se exit 12: inspeccionar artefacto
wardex art14 show <artifact-id>
wardex art14 mark-dispatched <artifact-id> --phase early-warning
```

**Caso de negócio: evidência para notificação à ENISA**

Quando o regulador notifica o fabricante e pede o registo de notificações Article 14 dos últimos 12 meses, a equipa de compliance executa:

```bash
wardex art14 list --since 2025-09-01 --format json
```

O output é um JSON com cada artefacto, respectivo HMAC, timestamps de detecção e dispatch, CVE, e componente afectado. É evidência formatada para entregar ao regulador sem ter de abrir um JIRA. O HMAC prova que os artefactos não foram alterados desde a sua criação, cumprindo o requisito de integridade da cadeia de custódia.

---

### ISO/IEC 27001:2022

**Caso técnico: gap analysis com inventário de activos**

O responsável de segurança executa a análise de gaps trimestral, cruzando a matriz de controlos documentados com os operacionais:

```bash
wardex assess iso27001-documented.yaml iso27001-implemented.yaml \
  --assets iso27001-assets.yaml \
  --framework iso27001 \
  -o markdown --out-file iso27001-gap-analysis.md
```

Identifica que o controlo A.8.12 (Information disposal) está documentado na política mas sem implementação em 3 dos 5 activos classificados. O roadmap prioriza automaticamente as acções correctivas.

**Caso de negócio: evidência para auditoria de recertificação**

Na auditoria externa ISO 27001, o auditor pede evidência de melhoria contínua (cláusula 10). A equipa de compliance apresenta o relatório de delta entre a avaliação anterior e a actual:

```bash
wardex assess Q1-controls.yaml Q2-controls.yaml \
  --assets assets.yaml \
  --framework iso27001 \
  -o markdown
```

O report mostra: "Global Coverage: 58% → 74%", "LayerDelta: Paper security reduziu de 32% para 18%". O auditor vê que a organização não só tem controlos documentados, como os está a implementar e a medir a evolução — exactamente o que a cláusula 10 exige.

---

## 3. Compliance Gap Analysis

Cruz o que a equipa de segurança declarou como política com o que está operacionalmente implementado, e compara ambos com o catálogo do framework.

### Input

Dois ficheiros YAML com o campo `layer` a identificar a origem:

```yaml
# documented-controls.yaml — políticas declaradas
- id: CTRL-IAM-001
  name: Multi-Factor Authentication
  layer: documented
  domains: [access_control]
  maturity: 4
  evidences:
    - type: policy
      ref: https://wiki.internal/sec/mfa-policy

# implemented-controls.yaml — controlos operacionais confirmados
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

O mesmo ID em ambos os ficheiros é o caso esperado. IDs presentes apenas num dos lados são o que interessa.

### Execução

```bash
wardex assess documented.yaml implemented.yaml \
  --framework iso27001 \
  -o markdown
```

### Output

O report separa os resultados em quatro estados:

| Estado | Significado |
|---|---|
| **Coberto** | Documentado e implementado com evidência operacional |
| **Paper security** | Documentado apenas — sem controlo implementado |
| **Shadow security** | Implementado sem política documentada |
| **Gap** | Ausente em ambas as camadas |

A secção `LayerDelta` quantifica o desvio entre intenção e execução.

### Com inventário de activos

```bash
wardex assess documented.yaml implemented.yaml \
  --assets assets.yaml \
  --framework nis2 \
  -o json --out-file posture.json
```

Produz uma tabela de conformidade por activo com criticidade, exposição, e owner.

---

## 4. Risk-Based Release Gate

O gate avalia cada vulnerabilidade no contexto do activo que a contém. O mesmo CVE pode ser ALLOW, WARN, ou BLOCK conforme o contexto.

### Modelo de risco

```
R(v, α) = (CVSS/10) × EPSS × C(α) × E(α) × (1 − Φ(α))
```

Onde:
- **C(α)** — criticidade do activo [0, 1]
- **E(α)** — exposição (internet-facing, requires_auth, etc.)
- **Φ(α)** — eficácia dos controlos compensatórios (cap 0.80, mínimo `1 − Φ` de 0.20)

R situa-se em [0, 1.5]. Thresholds definidos no `wardex-config.yaml`.

### Configuração

```yaml
# wardex-config.yaml
release_gate:
  enabled: true
  risk_appetite: 0.20        # Acima disto → BLOCK
  warn_above: 0.12           # Entre warn_above e risk_appetite → WARN
  mode: any                  # "any" | "aggregate"
  asset_context:
    criticality: 0.8
    internet_facing: true
    requires_auth: true
  compensating_controls:
    - type: waf
      effectiveness: 0.35
```

### Execução

```bash
wardex evaluate \
  --evidence vulns.yaml \
  --config wardex-config.yaml
```

### Interpretação do resultado

O gate produz uma decisão por vulnerabilidade com três bandas:

| Resultado | Exit code | Acção CI/CD |
|---|---|---|
| ALLOW | 0 | Pipeline prossegue |
| WARN | 0 | Pipeline prossegue com alerta |
| BLOCK | 10 | Pipeline falha — risco excede apetite |

### Calibração

Calibrado contra 237 CVEs reais com EPSS da FIRST.org:

| Perfil | Apetite | BLOCK | ALLOW |
|---|---|---|---|
| Banco Tier-1 (DORA) | 0.5 | 176 | 57 |
| Hospital (HIPAA) | 0.8 | 168 | 63 |
| Startup SaaS | 2.0 | 111 | 86 |
| Energia/Águas (NIS2) | 0.3 | 180 | 53 |

---

## 5. CRA Article 14 — Active Exploitation

Entra em vigor em Setembro de 2026. O Wardex implementa o pipeline completo de notificação.

### KEV Correlation

Correlaciona qualquer output de scanner contra o catálogo CISA Known Exploited Vulnerabilities:

```bash
curl -sSL https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  -o kev-catalogue.json

wardex convert grype grype-output.json --kev kev-catalogue.json
```

O output anota cada vulnerabilidade com `actively_exploited`, `dateAdded`, e notas CISA.

### Hard Stop (exit code 12)

Quando uma vulnerabilidade está activamente a ser explorada, o Wardex:

```bash
wardex evaluate --evidence vulns.yaml --config wardex-config.yaml
# Exit code: 12 (ActivelyExploited)
```

O código 12 é distinto do BLOCK normal (10) porque:
- Gera um artefacto de notificação Article 14 assinado com HMAC-SHA256
- Regista entrada de auditoria encadeada com os três prazos CRA
- Não pode ser substituído por aceitação de risco

### Ciclo de vida do artefacto

```bash
# Listar artefactos
wardex art14 list

# Inspeccionar artefacto
wardex art14 show <artifact-id>

# Verificar integridade HMAC
wardex art14 verify <artifact-id>

# Marcar early-warning como despachado
wardex art14 mark-dispatched <artifact-id> --phase early-warning

# Fechar o caso com confirmação de patch
wardex art14 finalize <artifact-id> --patch-date 2026-06-09T12:00:00Z
```

Cada artefacto é encadeado criptograficamente ao anterior, produzindo um audit trail append-only.

---

## 6. EPSS Enrichment

Quando o scanner não inclui EPSS, o Wardex assume EPSS 1.0 (pior caso) e bloqueia até validação explícita:

```bash
wardex enrich epss vulns.yaml --output epss-enrich.yaml

wardex evaluate \
  --evidence vulns.yaml \
  --epss-enrichment epss-enrich.yaml \
  --config wardex-config.yaml
```

O enriquecimento consulta `api.first.org` e assina cada resultado via HMAC-SHA256, prevenindo adulteração das probabilidades que afectam decisões de gate.

---

## 7. Risk Acceptance & Audit Chain

Quando o gate bloqueia e existe caso de negócio para prosseguir:

```bash
# Solicitar aceitação
wardex accept request \
  --report report.json \
  --cve CVE-2024-1234 \
  --accepted-by sec-lead@company.com \
  --justification "WAF mitiga o vector; patch previsto para Q3" \
  --expiry 90d

# Verificar integridade de todas as aceitações activas
wardex accept verify

# Listar aceitações activas
wardex accept list --active
```

Aceitações são assinadas com HMAC-SHA256 e registadas em log append-only (JSONL). O Wardex rejeita aceitações expiradas, adulteradas, ou cujo `wardex-config.yaml` sofreu drift desde a assinatura.

---

## 8. Governance: Trust Store & Sealed Config

Para conformidade DORA e cadeias de custódia não-repudiáveis, o Wardex permite selar as políticas de risco num envelope criptográfico assinado (`.wexstate`).

### Gerar chaves

```bash
# Gerar key pair para o CISO
wardex keygen --keyring ciso.wex

# Adicionar à trust store
wardex trust add --keyring ciso.wex --role admin

# Listar chaves autorizadas
wardex trust list
```

### Selar a configuração

```bash
# O CISO sela a política de risco
wardex config seal \
  --keyring ciso.wex \
  --input wardex-config.yaml \
  --out config.wexstate
```

### Avaliar com verificação do selo

```bash
wardex evaluate \
  --config config.wexstate \
  --evidence vulns.yaml \
  --strict
```

Com `--strict`, o Wardex rejeita qualquer configuração cujo selo não corresponda à trust store. Isto impede que alguém altere as políticas de risco em CI/CD sem aprovação executiva.

### Revogação

```bash
wardex trust revoke --key-id <key-id>
```

---

## 9. CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/wardex-gate.yml
name: Wardex Release Gate

on:
  pull_request:
    branches: [main]

jobs:
  risk-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Wardex
        run: go install github.com/had-nu/wardex@95eed886

      - name: Evaluate risk gate
        run: |
          wardex evaluate \
            --config .wardex/config.yaml \
            --evidence vulns.yaml \
            controls.yaml
        # Exit 0 = ALLOW, Exit 10 = BLOCK, Exit 12 = Active exploitation
```

### GitLab CI

```yaml
wardex-gate:
  image: golang:1.26
  script:
    - go install github.com/had-nu/wardex@95eed886
    - wardex evaluate --config .wardex/config.yaml --evidence vulns.yaml controls.yaml
  only:
    - merge_requests
```

### Pre-commit hook

```bash
#!/bin/sh
# .git/hooks/pre-commit
wardex policy validate wardex-config.yaml || exit 1
```

---

## 10. Exit Codes Reference

| Code | Nome | Acção |
|---|---|---|
| 0 | ALLOW | Pipeline prossegue |
| 3 | Integrity failure | Pipeline interrompe — configuração adulterada |
| 10 | Gate blocked | Pipeline falha — risco excede apetite |
| 11 | Compliance gap | Pipeline falha — cobertura de controlos insuficiente |
| 12 | Active exploitation | Pipeline falha — notificação CRA Article 14 necessária |

Os exit codes 10-12 devem ser tratados explicitamente na pipeline. O código 12 requer um path de notificação diferente de 10 — não podem ser tratados como o mesmo estado.

---

## 11. Troubleshooting

| Problema | Sintoma | Solução |
|---|---|---|
| HMAC mismatch | `invalid signature on enrichment file` | O `WARDEX_ACCEPT_SECRET` usado para assinar difere do ambiente actual |
| Framework não encontrado | `unsupported framework: xyz` | Usa um dos: `iso27001`, `nis2`, `dora` |
| Roadmap vazio | Secção Roadmap ausente do report | Todos os controlos do catálogo já estão cobertos — parabéns |
| Gate bloqueia tudo | BLOCK mesmo com CVSS baixo | EPSS em falta — Wardex assume 1.0 (fail-close). Corre `wardex enrich epss` |
| Selo rejeitado | `wexstate signature mismatch` | A configuração foi alterada desde que o CISO a selou. Reabrir approval |
| Exit code 12 inesperado | Pipeline falha com 12 | Executar `wardex art14 show` para inspeccionar o artefacto gerado |

---

*Wardex v2.1.0 · [github.com/had-nu/wardex](https://github.com/had-nu/wardex)*

