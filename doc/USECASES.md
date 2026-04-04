# Wardex — Casos de Uso Didáticos

**Versão de referência:** v1.7.1  
**Audiência:** Engenheiros de Plataforma, Security Champions, DevSecOps, Auditores de Conformidade

Este documento descreve os **cenários macro** que o Wardex já suporta hoje, com exemplos de ficheiros de input, outputs esperados e a lógica por detrás de cada decisão.

---

## Índice

1. [Cenário 1 — Gap Analysis de Conformidade (Baseline)](#cenário-1--gap-analysis-de-conformidade-baseline)
2. [Cenário 2 — Release Gate: BLOCK numa startup SaaS](#cenário-2--release-gate-block-numa-startup-saas)
3. [Cenário 3 — Release Gate: ALLOW com Controlos de Compensação](#cenário-3--release-gate-allow-com-controlos-de-compensação)
4. [Cenário 4 — EPSS em Falta → Fail-Close → Enrich](#cenário-4--epss-em-falta--fail-close--enrich)
5. [Cenário 5 — Aceitação de Risco Formal com Expiração](#cenário-5--aceitação-de-risco-formal-com-expiração)
6. [Cenário 6 — Multi-Framework: ISO 27001 vs NIS 2 vs DORA](#cenário-6--multi-framework-iso-27001-vs-nis-2-vs-dora)
7. [Cenário 7 — A Mesma CVE, 4 Contextos Diferentes](#cenário-7--a-mesma-cve-4-contextos-diferentes)
8. [Cenário 8 — Gestão de Políticas Locais (wardex policy)](#cenário-8--gestão-de-políticas-locais-wardex-policy)
9. [Cenário 9 — Snapshot e Delta de Maturidade entre Auditorias](#cenário-9--snapshot-e-delta-de-maturidade-entre-auditorias)
10. [Cenário 10 — Integração Grype → Wardex (Pipeline Completa)](#cenário-10--integração-grype--wardex-pipeline-completa)

---

## Cenário 1 — Gap Analysis de Conformidade (Baseline)

**Contexto:** Uma equipa de segurança quer saber o estado actual de conformidade ISO 27001 antes de uma auditoria externa. Têm uma lista de controlos implementados em YAML.

### Input: `meus-controlos.yaml`

```yaml
controls:
  - id: "CTRL-IDAM-01"
    name: "Multi-Factor Authentication"
    description: "MFA obrigatório em todos os sistemas de produção e VPN."
    maturity: 4
    domains: ["organizational", "people"]
    evidences:
      - type: "log"
        ref: "okta:mfa_enrolment_rate"
    context_weight: 1.8

  - id: "CTRL-NET-02"
    name: "Cloud Network Segmentation"
    description: "Isolamento de produção, staging e dev via AWS Security Groups."
    maturity: 5
    domains: ["technological"]
    evidences:
      - type: "architecture"
        ref: "aws:vpc_topology"
    context_weight: 1.5
```

### Comando

```bash
./bin/wardex --config=wardex-config.yaml meus-controlos.yaml
```

### Output Esperado (excerto Markdown)

```
## Executive Summary

| Metric                  | Value        |
|-------------------------|--------------|
| Global Compliance       | 34.4%        |
| Controls Covered        | 32 / 93      |
| Controls Partial        | 8 / 93       |
| Controls Gap            | 53 / 93      |

## Coverage by Domain

| Domain          | Covered | Partial | Gap | Maturity Avg |
|-----------------|---------|---------|-----|--------------|
| organizational  | 12/37   | 3       | 22  | 6.1          |
| technological   | 14/34   | 4       | 16  | 7.2          |
| people          | 4/8     | 1       | 3   | 5.8          |
| physical        | 2/14    | 0       | 12  | 4.1          |

## Roadmap (prioritized)

| Control | Name                          | Score | Reason  |
|---------|-------------------------------|-------|---------|
| A.8.12  | Data Leakage Prevention       | 8.1   | No evidence |
| A.8.23  | Web Filtering                 | 7.8   | No evidence |
| A.5.23  | Information security for cloud| 7.6   | No evidence |
```

### O que aprender

- **O Wardex não pede os 93 controlos à mão.** Ele aceita os que já tens implementados e identifica os *gaps* por correlação com o catálogo ISO 27001 interno.
- O **Roadmap** está ordenado por pontuação de risco — os itens no topo são os que têm maior impacto na conformidade global.
- Sem `--gate`, corre apenas em modo de *Gap Analysis* — sem impacto na pipeline.

---

## Cenário 2 — Release Gate: BLOCK numa startup SaaS

**Contexto:** Uma startup SaaS quer bloquear deploys quando o risco de release for inaceitável. O scanner de vulnerabilidades (Grype) encontrou uma CVE crítica com EPSS alto.

### Config: `wardex-config.yaml`

```yaml
organization:
  name: "Startup SaaS XYZ"
  sector: "saas"

release_gate:
  enabled: true
  mode: "any"
  risk_appetite: 2.0      # SaaS tem apetite moderado

  asset_context:
    criticality: 0.7
    internet_facing: true
    requires_auth: true
    environment: "production"

  compensating_controls:
    - type: "waf"
      effectiveness: 0.35
```

### Input de Vulnerabilidades: `vulns.yaml`

```yaml
vulnerabilities:
  - cve_id: "CVE-2024-1234"
    cvss_base: 9.1
    epss_score: 0.84
    component: "com.example:auth-lib:2.1.0"
    reachable: true
```

### Comando

```bash
./bin/wardex --config=wardex-config.yaml \
             --gate=vulns.yaml \
             meus-controlos.yaml
```

### Cálculo Interno (transparente)

```
EPSS Factor    = 0.84
Adjusted Score = 9.1 × 0.84  = 7.644
Exposure       = 1.0 (internet) × 0.8 (auth -0.2) × 1.0 (reachable) = 0.80
Compensating   = 0.35 (WAF)
Compensated    = 7.644 × (1 - 0.35) = 4.969
Final Risk     = 4.969 × 0.7 (criticality) × 0.80 (exposure) = 2.78  ← excede appetite 2.0
```

### Output e Exit Code

```
## Release Gate — Decision Breakdown

| CVE           | CVSS | EPSS | Release Risk | Decision      |
|---------------|------|------|--------------|---------------|
| CVE-2024-1234 | 9.1  | 0.84 | **2.8**      | [BLOCK] BLOCK |

Overall: BLOCK

Exit code: 2  (exitcodes.GateBlocked)
```

### O que aprender

- O CVSS sozinho (9.1) não bloqueia — o **risco contextualizado** (2.8 > 2.0) bloqueia.
- Se o `risk_appetite` fosse `4.0` (perfil Dev Sandbox), o resultado seria **ALLOW**.
- Exit code `2` garante que o **pipeline CI falha automaticamente**.

---

## Cenário 3 — Release Gate: ALLOW com Controlos de Compensação

**Contexto:** O mesmo CVE-2024-1234 (CVSS 9.1), mas o contexto de segurança tem controlos robustos: WAF + segmentação de rede + runtime protection. Resultado: ALLOW.

### Config com controlos robustos

```yaml
release_gate:
  enabled: true
  risk_appetite: 2.0

  asset_context:
    criticality: 0.7
    internet_facing: true
    requires_auth: true
    environment: "production"

  compensating_controls:
    - type: "waf"
      effectiveness: 0.35
    - type: "network_segmentation"
      effectiveness: 0.25
    - type: "runtime_protection"
      effectiveness: 0.20
```

### Cálculo

```
Compensating total = 0.35 + 0.25 + 0.20 = 0.80  (clamped ao máximo de 0.80)
Compensated Score  = 7.644 × (1 - 0.80) = 1.529
Final Risk         = 1.529 × 0.7 × 0.80 = 0.86  ← abaixo do appetite 2.0
```

### Output

```
| CVE           | CVSS | EPSS | Release Risk | Decision     |
|---------------|------|------|--------------|--------------|
| CVE-2024-1234 | 9.1  | 0.84 | **0.9**      | [OK] ALLOW   |

Overall: ALLOW

Exit code: 0
```

### O que aprender

- **O Wardex não ignora os controlos que já implementaste.** Um WAF + segmentação + EDR pode transformar um BLOCK num ALLOW.
- O tecto de `0.80` nos compensating controls evita gaming — nunca se anula 100% do risco.
- Este é o argumento central do Wardex contra o modelo "CVSS > 7.0 = bloqueia tudo".

---

## Cenário 4 — EPSS em Falta → Fail-Close → Enrich

**Contexto:** O scanner upstream não fornece EPSS. O Wardex faz *fail-close* (assume EPSS=1.0) e bloqueia. A equipa usa `wardex enrich epss` para buscar os valores reais e desbloquear.

### Vulnerabilidades sem EPSS

```yaml
vulnerabilities:
  - cve_id: "CVE-2024-9999"
    cvss_base: 5.3
    epss_score: 0.0     # ← ausente / não fornecido pelo scanner
    component: "log-lib:3.2.1"
    reachable: true
```

### Comportamento sem EPSS

```
EPSS Factor    = 1.0  (fail-close — assume pior caso)
Adjusted Score = 5.3 × 1.0 = 5.3
Final Risk     = 5.3 × 0.7 × 0.80 = 2.97  ← excede appetite 2.0 → BLOCK

[HINT] 1 vulnerabilities lacked EPSS scores and defaulted to worst-case (1.0).
       Run 'wardex enrich epss vulns.yaml' to fetch real probabilities from FIRST.org.
```

### Passo de enriquecimento

```bash
# Fetch EPSS real da FIRST.org e assina o resultado com HMAC-SHA256
WARDEX_ACCEPT_SECRET=mysecret \
  ./bin/wardex enrich epss vulns.yaml --output epss-enriched.yaml

# Reutilizar na pipeline com payload assinado
./bin/wardex --config=wardex-config.yaml \
             --gate=vulns.yaml \
             --epss-enrichment=epss-enriched.yaml \
             meus-controlos.yaml
```

### Output após enriquecimento (EPSS real = 0.03)

```
[INFO] Applied signed EPSS Enrichment for CVE-2024-9999: 0.030000

EPSS Factor    = 0.03
Adjusted Score = 5.3 × 0.03 = 0.159
Final Risk     = 0.159 × 0.7 × 0.80 = 0.09  ← ALLOW

| CVE           | CVSS | EPSS | Release Risk | Decision    |
|---------------|------|------|--------------|-------------|
| CVE-2024-9999 | 5.3  | 0.03 | **0.1**      | [OK] ALLOW  |
```

### O que aprender

- **EPSS desconhecido ≠ EPSS zero.** O Wardex assume o pior (1.0) para forçar revisão humana.
- O enriquecimento é **assinado criptograficamente** — a pipeline rejeita ficheiros adulterados.
- Este padrão é o *Human-in-the-Loop* (HITL): a máquina bloqueia, o humano enriquece e valida.

---

## Cenário 5 — Aceitação de Risco Formal com Expiração

**Contexto:** Uma CVE está a bloquear o release, mas a equipa de segurança decidiu formalmente aceitar o risco. O CISO assina a exceção por 30 dias.

```bash
# Passo 1: Gerar o relatório com o gate
./bin/wardex --config=wardex-config.yaml \
             --gate=vulns.yaml \
             --output=json \
             --out-file=report.json \
             meus-controlos.yaml

# Passo 2: Solicitar aceitação formal
WARDEX_ACCEPT_SECRET=mysecret \
  ./bin/wardex accept request \
    --report report.json \
    --cve CVE-2024-1234 \
    --accepted-by ciso@empresa.com \
    --justification "CVE mitigada por WAF + patch previsto para 2024-04-15" \
    --expires 30d

# Passo 3: Verificar integridade de todas as aceitações ativas
WARDEX_ACCEPT_SECRET=mysecret \
  ./bin/wardex accept verify
```

### Ficheiro `wardex-acceptances.yaml` gerado

```yaml
acceptances:
  - cve: "CVE-2024-1234"
    accepted_by: "ciso@empresa.com"
    justification: "CVE mitigada por WAF + patch previsto para 2024-04-15"
    expires_at: "2024-04-29T00:00:00Z"
    hmac: "a3f8b2..."
    revoked: false
```

### Pipeline com aceitações ativas

```bash
# A CVE aceite é ignorada pelo gate automaticamente
./bin/wardex --config=wardex-config.yaml \
             --gate=vulns.yaml \
             meus-controlos.yaml

# [INFO] CVE CVE-2024-1234 is covered by an active risk acceptance and will be ignored.
# Overall: ALLOW
```

### O que aprender

- As aceitações têm **expiração obrigatória** — não existem exceções permanentes por design.
- O HMAC-SHA256 impede adulteração retroativa do registo de aceitações.
- O log de auditoria (`wardex-accept-audit.log`) é *append-only* para rastreabilidade SOC 2 / ISO 27001.

---

## Cenário 6 — Multi-Framework: ISO 27001 vs NIS 2 vs DORA

**Contexto:** Uma organização financeira (banco tier-1) precisa de relatórios separados, um por framework, para diferentes audiências de compliance.

```bash
# Relatório ISO 27001 — para auditores de certificação
./bin/wardex --framework iso27001 \
             --config=wardex-config.yaml \
             --output=markdown \
             --out-file=report-iso27001.md \
             frameworks/iso27001/*.yml

# Relatório NIS 2 — para o CISO e autoridades regulatórias EU
./bin/wardex --framework nis2 \
             --config=wardex-config.yaml \
             --output=markdown \
             --out-file=report-nis2.md \
             frameworks/nis2/*.yml

# Relatório DORA — para o Chief Risk Officer (CRO)
./bin/wardex --framework dora \
             --config=wardex-config.yaml \
             --output=markdown \
             --out-file=report-dora.md \
             frameworks/dora/*.yml

# Relatório SOC 2 — para clientes e parceiros SaaS
./bin/wardex --framework soc2 \
             --config=wardex-config.yaml \
             --output=markdown \
             --out-file=report-soc2.md \
             frameworks/soc2/*.yml
```

### Diferença de cobertura por framework

Os **mesmos controlos** implementados produzem coberturas diferentes porque cada framework tem perguntas diferentes:

| Framework   | Controlos Catalogados | Foco Principal                            |
|-------------|----------------------|-------------------------------------------|
| `iso27001`  | 93                   | Gestão de Segurança da Informação holística|
| `nis2`      | ~40                  | Resiliência de redes e sistemas críticos  |
| `soc2`      | ~60                  | Confiança e disponibilidade de serviços   |
| `dora`      | ~30                  | Resiliência operacional digital (BFSI)    |

### O que aprender

- O mesmo controlo CTRL-IDAM-01 (MFA) cobre **A.9.4.2** (ISO), **Art.21.2(j)** (NIS 2) e **Art.9** (DORA) simultaneamente.
- Um investimento em controlos pode satisfazer **múltiplos reguladores** — a análise de correlação do Wardex torna isto visível.

---

## Cenário 7 — A Mesma CVE, 4 Contextos Diferentes

**Demonstração** de como o contexto organizacional altera radicalmente a decisão para **CVE-2021-44228** (Log4Shell, CVSS 10.0, EPSS 0.94).

### Comandos por perfil

```bash
# Banco Tier-1 (DORA, criticality=1.0, appetite=0.5)
./bin/wardex --config=config-bank.yaml --gate=log4shell.yaml controlos.yaml
# → Final Risk: 14.2 → BLOCK

# Startup SaaS (criticality=0.7, appetite=2.0)
./bin/wardex --config=config-saas.yaml --gate=log4shell.yaml controlos.yaml
# → Final Risk: 2.5 → BLOCK (mas por pouco)

# Hospital (HIPAA, criticality=0.9, appetite=0.8)
./bin/wardex --config=config-hospital.yaml --gate=log4shell.yaml controlos.yaml
# → Final Risk: 7.9 → BLOCK

# Dev Sandbox (criticality=0.3, internet_facing=false, appetite=4.0)
./bin/wardex --config=config-dev.yaml --gate=log4shell.yaml controlos.yaml
# → Final Risk: 0.3 → ALLOW
```

### Tabela de decisões

| Perfil          | Apetite | Risk Final | Decisão   |
|-----------------|---------|------------|-----------|
| 🏦 Banco Tier-1  | 0.5     | **14.2**   | ❌ BLOCK  |
| 🏥 Hospital       | 0.8     | **7.9**    | ❌ BLOCK  |
| 🚀 SaaS           | 2.0     | **2.5**    | ❌ BLOCK  |
| 🔧 Dev Sandbox    | 4.0     | **0.3**    | ✅ ALLOW  |

### O que aprender

- **Log4Shell não é universalmente equivalente.** Num sandbox de dev sem dados reais, é aceitável aguardar o patch na próxima Sprint.
- No banco, o mesmo CVE tem risco `28×` maior que no sandbox — justificando um plano de resposta imediata.
- Esta é a proposta central do Wardex: **contexto importa mais que o CVSS bruto**.

---

## Cenário 8 — Gestão de Políticas Locais (wardex policy)

**Contexto:** Uma equipa quer gerir o estado de conformidade dos controlos ISO 27001 A.8 em ficheiros YAML versionados no Git, sem edição manual propensa a erros.

### Estrutura recomendada

```
frameworks/
  iso27001/
    organizational_controls.yml   # A.5
    people_controls.yml           # A.6
    physical_controls.yml         # A.7
    technological_controls.yml    # A.8
  soc2/
    trust_services.yml            # Common Criteria (CC)
  nis2/
    cyber_hygiene.yml             # Artigo 21
  dora/
    resilience_controls.yml       # Artigos 5 e 9
```

### Workflow de dia-a-dia

```bash
# 1. Validar todos os ficheiros antes de fazer commit
wardex policy validate frameworks/iso27001/
# ✓ 4 domain file(s), 42 control(s) — all valid in "frameworks/iso27001/"

# 2. Verificar estado actual dos controlos
wardex policy list frameworks/iso27001/

# ID     TITLE                     STATUS         OWNER          LAST ASSESSED
# --     -----                     ------         -----          -------------
# A.8.1  User endpoint devices     compliant      IT Operations  2025-02-15
# A.8.2  Privileged access rights  partial        Security Team  2025-01-10
# A.8.3  Info access restriction   non_compliant  IT Operations  2025-01-10

# 3. Após implementar um controlo, actualizar sem editar YAML manualmente
wardex policy add \
  --file frameworks/iso27001/technological_controls.yml \
  --id A.8.3 \
  --title "Information access restriction" \
  --status compliant \
  --owner "Security Team" \
  --note "RBAC model deployed via AWS IAM. Quarterly review scheduled."

# Updated control "A.8.3" in "frameworks/iso27001/technological_controls.yml"
```

### O que aprender

- `wardex policy validate` pode ser adicionado como **pre-commit hook** ou step de CI, garantindo que nenhum YAML quebrado entra no repositório.
- O histórico de mudanças de status dos controlos fica naturalmente **rastreado no Git** (quem alterou, quando, porquê — via commit message).
- O schema é rigoroso: `status` só aceita `compliant | partial | non_compliant | not_applicable`.

---

## Cenário 9 — Snapshot e Delta de Maturidade entre Auditorias

**Contexto:** Uma equipa quer demonstrar evolução de maturidade entre a auditoria de Janeiro e a de Março.

```bash
# Janeiro: primeira execução — cria snapshot
./bin/wardex --config=wardex-config.yaml \
             --snapshot-file=snapshot-jan.json \
             --output=markdown \
             --out-file=report-jan.md \
             controlos-jan.yaml

# Março: segunda execução — compara com snapshot anterior
./bin/wardex --config=wardex-config.yaml \
             --snapshot-file=snapshot-jan.json \
             --output=markdown \
             --out-file=report-mar.md \
             controlos-mar.yaml
```

### Secção Delta no relatório de Março

```markdown
## Delta Since Last Run

| Metric               | January   | March     | Change     |
|----------------------|-----------|-----------|------------|
| Global Coverage      | 34.4%     | 58.1%     | +23.7% ↑  |
| Controls Covered     | 32 / 93   | 54 / 93   | +22 ↑     |
| Controls Partial     | 8 / 93    | 12 / 93   | +4 ↑      |
| Controls Gap         | 53 / 93   | 27 / 93   | -26 ↓     |
```

### O que aprender

- Os snapshots são utilizados para **comprovar progresso** a auditores externos — evidência objectiva de melhoria contínua exigida pela ISO 27001 Cláusula 10.
- Usa `--no-snapshot` para correr sem escrever/ler snapshot (útil em pipelines temporárias ou dry-runs).
- Os ficheiros de snapshot são JSON portáveis — podem ser arquivados, versionados ou partilhados com consultores externos.

---

## Cenário 10 — Integração Grype → Wardex (Pipeline Completa)

**Contexto:** Pipeline de CI/CD completa: Grype faz o scan do container, converte o output para formato Wardex, e o gate valida antes do deploy.

### `.github/workflows/security-gate.yml`

```yaml
name: Security Release Gate

on:
  push:
    branches: [main]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      # 1. Instalar Wardex
      - name: Install Wardex
        run: |
          VERSION="v1.7.1"
          curl -sSL \
            "https://github.com/had-nu/wardex/releases/download/${VERSION}/wardex_Linux_x86_64.tar.gz" \
            | tar -xz
          sudo mv wardex /usr/local/bin/

      # 2. Scan com Grype
      - name: Scan Container with Grype
        run: |
          grype myapp:latest -o json > grype-output.json

      # 3. Converter output Grype → formato Wardex
      - name: Convert Grype Output
        run: |
          wardex convert grype grype-output.json --output wardex-vulns.yaml

      # 4. Enriquecer EPSS (Human-in-the-Loop)
      - name: Enrich EPSS Scores
        env:
          WARDEX_ACCEPT_SECRET: ${{ secrets.WARDEX_ACCEPT_SECRET }}
        run: |
          wardex enrich epss wardex-vulns.yaml --output epss-enriched.yaml

      # 5. Avaliar o Release Gate
      - name: Evaluate Release Gate
        env:
          WARDEX_ACCEPT_SECRET: ${{ secrets.WARDEX_ACCEPT_SECRET }}
          WARDEX_ACTOR: ${{ github.actor }}
        run: |
          wardex \
            --config ./wardex-config.yaml \
            --gate wardex-vulns.yaml \
            --epss-enrichment epss-enriched.yaml \
            --framework iso27001 \
            --output markdown \
            --out-file wardex-report.md \
            ./frameworks/iso27001/*.yml

      # 6. Publicar relatório no PR
      - name: Upload Security Report
        uses: actions/upload-artifact@65c4c4a1ddce5f7f3d7f6de4d45ea3c70a2cca2f # v4
        with:
          name: wardex-security-report
          path: wardex-report.md
```

### Fluxo de dados

```
Container Image
    │
    ▼ grype scan
grype-output.json
    │
    ▼ wardex convert grype
wardex-vulns.yaml  (formato nativo)
    │
    ▼ wardex enrich epss
epss-enriched.yaml  (assinado HMAC-SHA256)
    │
    ▼ wardex --gate --epss-enrichment
─────────────────────────────────────────
  Gap Analysis + Release Gate Decision
─────────────────────────────────────────
    │
    ├─ Exit 0  → Deploy continua ✅
    ├─ Exit 2  → Deploy bloqueado ❌ (GateBlocked)
    └─ Exit 3  → Compliance fail ❌ (ComplianceFail)
```

### O que aprender

- A pipeline completa cobre **scanning → conversão → enriquecimento → gate** sem intervenção manual.
- Os exit codes `0 / 2 / 3` mapeiam directamente para sucesso/falha no CI — sem scripts de parsing de output.
- A combinação Grype + Wardex cobre tanto **vulnerabilidades técnicas** (CVEs em dependências) como **maturidade de conformidade** (ISO 27001 gap) num único report.

---

## Referência Rápida: Exit Codes

| Código | Nome             | Quando ocorre                                          |
|--------|------------------|--------------------------------------------------------|
| `0`    | `OK`             | Gap Analysis e Gate passaram sem problemas             |
| `2`    | `GateBlocked`    | Uma ou mais CVEs excederam o `risk_appetite`           |
| `3`    | `ComplianceFail` | Um ou mais gaps excederam o valor `--fail-above`       |

## Referência Rápida: Fórmula de Risco

```
FinalRisk = (CVSS × EPSS) × (1 - CompensatingControls) × Criticality × Exposure

Exposure = InternetWeight × (1 - AuthReduction) × (1 - ReachabilityReduction)

Onde:
  InternetWeight    = 1.0 (exposto) | 0.6 (interno) | 0.3 (development)
  AuthReduction     = 0.2 se requires_auth = true
  ReachabilityReduction = 0.5 se reachable = false
  CompensatingControls  = clamped em 0.80 máximo
  EPSS ausente      = 1.0 (fail-close)
```

---

*Documentação gerada com base no código fonte de [Wardex v1.7.1](https://github.com/had-nu/wardex). Para questões, consulte o [Wiki](https://github.com/had-nu/wardex/wiki) ou abra uma Issue.*
