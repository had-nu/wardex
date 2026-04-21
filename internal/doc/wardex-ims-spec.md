# Wardex × IMS Certification — Especificação Completa
## `wardex convert soa` · `wardex scaffold` · Gitflow · Lifecycle de Comunicação

> **Versão:** draft-v1 · **Base de código:** Wardex v1.6.1
> **Âmbito:** ISO 27001:2022, ISO 22301, ISO 9001 · IMS integrado

---

## Índice

1. [Schema do Statement of Applicability (SoA Excel)](#1-schema-do-statement-of-applicability)
2. [Especificação: `wardex convert soa`](#2-especificação-wardex-convert-soa)
3. [Especificação: `wardex scaffold`](#3-especificação-wardex-scaffold)
4. [Mapeamento SoA → controls.yaml](#4-mapeamento-soa--controlsyaml)
5. [Estrutura de repositório IMS](#5-estrutura-de-repositório-ims)
6. [Gitflow do ciclo de certificação](#6-gitflow-do-ciclo-de-certificação)
7. [Ciclo de comunicação por fase](#7-ciclo-de-comunicação-por-fase)
8. [Workflow completo pré-auditoria](#8-workflow-completo-pré-auditoria)

---

## 1. Schema do Statement of Applicability

Um SoA ISO 27001 suportado pelo Wardex deve ser exportado em formato CSV (`.csv`). O converter suporta dois perfis de colunas baseados no *Header* da primeira linha: **mínimo** (obrigatório pela norma) e **estendido** (com campos operacionais comuns).

### 1.1 Colunas obrigatórias (perfil mínimo)

| Coluna CSV | Nomes alternativos aceites | Tipo | Obrigatório |
|---|---|---|---|
| `Control ID` | `Ref`, `Clause`, `ID`, `Control Ref` | string | ✅ |
| `Control Name` | `Name`, `Control`, `Title` | string | ✅ |
| `Applicable` | `Applicability`, `Include`, `In Scope` | bool* | ✅ |
| `Justification` | `Justification for Inclusion/Exclusion`, `Reason` | string | ✅ |
| `Implementation Status` | `Status`, `Implementation`, `Impl. Status` | enum** | ✅ |

*`bool` aceita: `Yes/No`, `Y/N`, `True/False`, `1/0`, `Applicable/Not Applicable`
**enum aceita: `Implemented`, `Partially Implemented`, `Planned`, `Not Implemented`, `Not Applicable`

### 1.2 Colunas estendidas (perfil operacional)

| Coluna CSV | Nomes alternativos aceites | Tipo | Default se ausente |
|---|---|---|---|
| `Owner` | `Responsible`, `Control Owner`, `Accountable` | string | `""` |
| `Evidence Ref` | `Evidence`, `Evidence Reference`, `Proof` | string (pipe-sep) | `[]` |
| `Evidence Type` | `Evidence Kind`, `Type` | string (pipe-sep) | `"document"` |
| `Risk Reference` | `Risk ID`, `Risk Ref`, `Threat Ref` | string | `""` |
| `Context Weight` | `Weight`, `Priority`, `Criticality Weight` | float64 | `1.0` |
| `Weight Justification` | `Weight Reason`, `Priority Reason` | string | `""` |
| `Framework` | `Standard`, `Norm` | string | inferido do `--framework` |
| `Domain` | `Category`, `Annex Domain`, `Area` | string (pipe-sep) | inferido do catálogo |
| `Last Review Date` | `Review Date`, `Last Updated` | date | `""` |
| `Notes` | `Comments`, `Observations` | string | `""` |

### 1.3 Mapeamento de `Implementation Status` → `Maturity`

```
Not Applicable      → excluído do output (--include-na para forçar inclusão)
Not Implemented     → maturity: 1
Planned             → maturity: 2
Partially Implemented → maturity: 3
Implemented         → maturity: 4
Fully Optimised     → maturity: 5  (extensão operacional, não obrigatória na norma)
```

O maturity 5 ("Optimised") requer declaração explícita no SoA ou flag
`--allow-maturity-5`. Por defeito, `Implemented` mapeia para 4 — reflectindo
que maturidade máxima exige evidência de melhoria contínua documentada, não
apenas implementação.

---

## 2. Especificação: `wardex convert soa`

### 2.1 Interface de linha de comandos

```
wardex convert soa <input.csv> [flags]

Flags:
  --framework string       Framework alvo: iso27001|iso22301|iso9001|all
                           (default: iso27001; "all" gera um ficheiro por framework)
  --output string          Path do ficheiro de saída ou "stdout"
                           (default: controls-<framework>.yaml)
  --sheet string           Nome da folha Excel a usar (default: primeira folha)
  --profile string         Perfil de colunas: minimal|extended|auto
                           (default: auto — detecção por headers)
  --include-na             Incluir controlos marcados como Not Applicable
                           com maturity: 0 e flag na_justified: true
  --allow-maturity-5       Permitir maturity: 5 para "Fully Optimised"
  --domain-map string      Path para ficheiro de mapeamento domínio→domain
                           (para headers não-standard em outras línguas)
  --dry-run                Valida e mostra preview sem escrever ficheiro
  --strict                 Falha se encontrar colunas obrigatórias em falta
                           (default: warn e continua com defaults)
  --audit-log              Escreve entrada no wardex-accept-audit.log com hash
                           do SoA importado (rastreabilidade de origem)
```

### 2.2 Detecção automática de colunas (`--profile auto`)

O converter normaliza os headers da primeira linha:

```go
// Algoritmo de detecção
func detectColumn(headers []string, candidates []string) int {
    for i, h := range headers {
        normalized := strings.ToLower(strings.TrimSpace(h))
        for _, c := range candidates {
            if strings.Contains(normalized, c) {
                return i  // primeiro match ganha
            }
        }
    }
    return -1  // não encontrado
}
```

Headers em português também são detectados:

```
"Controlo" | "ID Controlo"          → Control ID
"Nome"     | "Nome do Controlo"      → Control Name
"Aplicável" | "Aplicabilidade"       → Applicable
"Justificação" | "Justificativa"     → Justification
"Estado" | "Estado de Implementação" → Implementation Status
"Responsável" | "Proprietário"       → Owner
"Evidência" | "Evidências"           → Evidence Ref
```

Para organizações com SoA em árabe, francês, ou espanhol: fornecer
`--domain-map` apontando para um YAML de tradução de termos.

### 2.3 Exemplo de execução

```bash
### 2.3 Exemplo de execução

```bash
# Conversão básica a partir de CSV exportado
wardex convert soa Statement_of_Applicability_v3.csv \
  --framework iso27001 \
  --output controls/iso27001-from-soa.yaml

# Múltiplos frameworks num único SoA
wardex convert soa IMS_SoA_2025.csv \
  --framework all \
  --output controls/

# Dry-run para validar antes de comprometer
wardex convert soa SoA.xlsx --dry-run --strict
```

### 2.4 Output do dry-run

```
wardex convert soa — dry run

Input:  Statement_of_Applicability_v3.csv
Row count: 93 rows detected
Profile: extended (14/16 expected columns found)

Column mapping:
  ✓ Control ID        → col A  (header: "Ref")
  ✓ Control Name      → col B  (header: "Control Name")
  ✓ Applicable        → col C  (header: "Applicable (Y/N)")
  ✓ Justification     → col D  (header: "Justification for Inclusion")
  ✓ Status            → col E  (header: "Implementation Status")
  ✓ Owner             → col F  (header: "Control Owner")
  ✓ Evidence Ref      → col H  (header: "Evidence Reference")
  ✗ Context Weight    → not found  (default: 1.0)
  ✗ Risk Reference    → not found  (default: "")

Row analysis:
  93  total rows
  88  applicable controls  (will generate controls)
   5  not applicable       (excluded; use --include-na to override)
   0  parse errors

Maturity distribution:
  maturity: 1  →  7 controls  (Not Implemented)
  maturity: 2  →  4 controls  (Planned)
  maturity: 3  → 19 controls  (Partial)
  maturity: 4  → 58 controls  (Implemented)

Output preview (first 3 controls):
  CTRL-A.5.1  Information security policies   maturity:4  domains:[organizational]
  CTRL-A.5.2  Information security roles       maturity:3  domains:[organizational,people]
  CTRL-A.5.3  Segregation of duties            maturity:4  domains:[organizational]

Run without --dry-run to write controls/iso27001-from-soa.yaml
```

### 2.5 Tratamento de erros e warnings

```
Nível WARN (continua, regista):
  - Coluna estendida não encontrada (usa default)
  - Status value não reconhecido (usa maturity: 1, regista linha)
  - Evidence Ref presente mas Evidence Type ausente (usa "document")
  - Control ID não corresponde a nenhum ID do catálogo embebido

Nível ERROR (falha se --strict, warn se não):
  - Coluna obrigatória não encontrada
  - Ficheiro CSV não formatado correctamente ou erro de parsing

Nível FATAL (sempre falha):
  - Ficheiro de input não existe
  - --framework não reconhecido
  - Sheet completamente vazia
```

---

## 3. Especificação: `wardex scaffold`

O `wardex scaffold` gera templates `controls.yaml` pré-preenchidos com a estrutura
do catálogo, deixando campos de implementação em branco para preenchimento.
É o ponto de entrada para organizações sem SoA existente.

### 3.1 Interface de linha de comandos

```
wardex scaffold [flags]

Flags:
  --framework string    Framework: iso27001|iso22301|iso9001|all
                        (default: iso27001)
  --domain string       Domínio específico: technological|organizational|
                        people|physical|all (default: all)
  --output string       Path do ficheiro de saída
                        (default: controls-scaffold-<framework>.yaml)
  --mode string         Modo de template: minimal|full
                        minimal: só campos obrigatórios com TODOs
                        full: todos os campos com comentários explicativos
                        (default: full)
  --maturity int        Maturity default para todos os controlos (1-4)
                        (default: 1 — assume não implementado)
  --annotate            Inclui comentários inline com guia de preenchimento
                        (default: true em --mode full)
```

### 3.2 Exemplo de output (`--mode full`, domínio technological)

```yaml
# Generated by: wardex scaffold --framework iso27001 --domain technological
# Generated at: 2026-03-06T14:00:00Z
# Catalog: ISO/IEC 27001:2022 Annex A — Technological Controls
# Instructions: Fill in each control that applies to your organization.
#   - Set maturity: 1-5 based on implementation level
#   - Add at least one evidence reference per control
#   - Set context_weight: 0.5-2.0 based on business criticality
#   - Remove controls with no applicability after review

controls:

  # ── A.8 — TECHNOLOGICAL CONTROLS ─────────────────────────────────────────
  # 34 controls in this domain. Review all for applicability.

  - id: "CTRL-A.8.1"                  # Do not change — catalog reference
    name: "User Endpoint Devices"
    description: ""                   # TODO: Describe how endpoint devices
                                      # are managed in your organisation
    framework: iso27001
    domains:
      - technological
    maturity: 1                       # TODO: 1=initial 2=planned 3=partial
                                      #       4=implemented 5=optimised
    evidences: []                     # TODO: Add at least one reference
                                      # Examples:
                                      #   - type: policy
                                      #     ref: "confluence:IT-POL-001"
                                      #   - type: log
                                      #     ref: "intune:device_compliance"
                                      #   - type: procedure
                                      #     ref: "sharepoint:endpoint-mgmt"
    context_weight: 1.0               # TODO: Adjust 0.5-2.0
                                      # 0.5 = lower priority in your context
                                      # 2.0 = critical for your business
    weight_justification: ""          # TODO: Explain context_weight value

  - id: "CTRL-A.8.2"
    name: "Privileged Access Rights"
    description: ""
    framework: iso27001
    domains:
      - technological
      - organizational
    maturity: 1
    evidences: []
    context_weight: 1.0
    weight_justification: ""

  # ... (32 more controls in this domain)
```

### 3.3 Modo minimal

```yaml
# wardex scaffold --framework iso27001 --mode minimal --domain technological
controls:
  - id: "CTRL-A.8.1"
    name: "User Endpoint Devices"
    description: ""         # TODO
    maturity: 1             # TODO: 1-5
    domains: [technological]
    evidences: []           # TODO: [{type: policy, ref: "..."}]
    context_weight: 1.0     # TODO: 0.5-2.0

  - id: "CTRL-A.8.2"
    name: "Privileged Access Rights"
    description: ""
    maturity: 1
    domains: [technological, organizational]
    evidences: []
    context_weight: 1.0
```

---

## 4. Mapeamento SoA → controls.yaml

Tabela completa de mapeamento campo a campo:

| Campo SoA Excel | Campo `controls.yaml` | Transformação |
|---|---|---|
| Control ID (`A.5.1`) | `id` | Prefixo `CTRL-` + valor: `CTRL-A.5.1` |
| Control Name | `name` | Directo |
| Justification | `description` | Directo (truncado em 500 chars) |
| Implementation Status | `maturity` | Enum → int (ver §1.3) |
| Domain (ou inferido do catálogo) | `domains` | Split por `\|` ou `,`; lowercase; trim |
| Evidence Ref | `evidences[].ref` | Split por `\|`; trim cada ref |
| Evidence Type | `evidences[].type` | Split por `\|`; lowercase; default `"document"` |
| Context Weight | `context_weight` | float64; clamp [0.5, 2.0]; default 1.0 |
| Weight Justification | `weight_justification` | Directo |
| Owner | `weight_justification` (append) | `"Owner: {owner}. " + existing` |
| `--framework` flag | `framework` | Directo |
| Not Applicable rows | excluídas | A menos que `--include-na` |

### 4.1 Exemplo de linha SoA → YAML gerado

**Linha SoA:**

| Ref | Control Name | Applicable | Justification | Status | Owner | Evidence Reference | Evidence Type | Weight |
|---|---|---|---|---|---|---|---|---|
| A.8.8 | Management of technical vulnerabilities | Yes | Critical for fintech regulatory compliance | Partially Implemented | ops-team@company.com | github:security-scan.yml \| jira:SEC-board | pipeline \| log | 1.8 |

**YAML gerado:**

```yaml
- id: "CTRL-A.8.8"
  name: "Management of technical vulnerabilities"
  description: "Critical for fintech regulatory compliance"
  framework: iso27001
  domains:
    - technological
  maturity: 3
  evidences:
    - type: pipeline
      ref: "github:security-scan.yml"
    - type: log
      ref: "jira:SEC-board"
  context_weight: 1.8
  weight_justification: "Owner: ops-team@company.com."
```

---

## 5. Estrutura de repositório IMS

Um repositório Git dedicado ao IMS separa a configuração do ciclo de vida
da certificação do repositório de código produto.

```
ims-controls/
│
├── README.md                      # Visão geral, como contribuir, contactos
├── wardex-config.yaml             # Configuração global do Wardex
│
├── controls/                      # Declaração de controlos por framework
│   ├── iso27001/
│   │   ├── technological.yaml     # A.8.x controls
│   │   ├── organizational.yaml    # A.5.x, A.6.x controls
│   │   ├── people.yaml            # A.6.x people controls
│   │   └── physical.yaml          # A.7.x controls
│   ├── iso22301/
│   │   ├── leadership.yaml
│   │   ├── planning.yaml
│   │   └── operations.yaml
│   └── iso9001/
│       ├── context.yaml
│       ├── support.yaml
│       └── operations.yaml
│
├── soa/                           # Sources originais do SoA
│   ├── iso27001-soa-v3.xlsx       # SoA original (source of truth externo)
│   ├── iso22301-soa-v2.xlsx
│   └── iso9001-soa-v1.xlsx
│
├── acceptances/                   # Aceitações de risco e NCs
│   ├── wardex-acceptances.yaml    # Risk acceptances (HMAC-signed)
│   └── wardex-accept-audit.log   # JSONL audit trail
│
├── audits/                        # Artefactos de auditoria por ciclo
│   ├── 2025/
│   │   ├── internal-q1/
│   │   │   ├── scope.md
│   │   │   ├── wardex-report.json  # snapshot do momento da auditoria
│   │   │   └── findings.md
│   │   └── external-cert/
│   │       ├── audit-plan.md
│   │       └── wardex-report.json
│   └── 2026/
│       └── internal-q1/
│
├── snapshots/                     # Snapshots automáticos por run
│   ├── .wardex_snapshot_iso27001.json
│   ├── .wardex_snapshot_iso22301.json
│   └── .wardex_snapshot_iso9001.json
│
├── reports/                       # Relatórios gerados (git-ignored ou não)
│   └── .gitkeep
│
├── scripts/                       # Automação do ciclo
│   ├── pre-audit-check.sh         # Corre todos os frameworks, gera relatórios
│   ├── enrich-epss.py             # Enriquecimento EPSS (se usado com gate)
│   └── notify-expiry.sh           # Wrapper para check-expiry com notificação
│
└── .github/
    ├── workflows/
    │   ├── compliance-check.yml   # Run diário de gap analysis
    │   ├── pre-audit.yml          # Triggered manualmente 8 semanas antes
    │   └── expiry-check.yml       # Check diário de aceitações/NCs
    └── PULL_REQUEST_TEMPLATE/
        ├── control-update.md      # Template para PRs de actualização de controlos
        ├── evidence-update.md     # Template para PRs de evidências
        └── nc-closure.md          # Template para PRs de closure de NCs
```

---

## 6. Gitflow do ciclo de certificação

O repositório IMS usa uma variante do Gitflow adaptada ao ritmo de auditorias
em vez de releases de software.

### 6.1 Branches permanentes

```
main          → estado auditado e aprovado
              → protegido: requer PR + review de GRC owner
              → tagged em cada auditoria concluída

develop       → trabalho em curso
              → CI corre gap analysis a cada push
              → PRs de feature → develop

audit/YYYY-TYPE → branch de preparação de auditoria
              → criada 8 semanas antes da auditoria
              → mergeada em main após conclusão da auditoria
              → ex: audit/2026-internal-q1, audit/2026-external-cert
```

### 6.2 Branches de trabalho

```
feature/CTRL-ID-descricao      → novo controlo ou actualização de controlo
  ex: feature/CTRL-A.8.8-wardex-gate

evidence/CTRL-ID-tipo          → nova evidência para controlo existente
  ex: evidence/CTRL-A.8.8-pipeline-ref

fix/CTRL-ID-correcao           → correcção de dados incorrectos
  ex: fix/CTRL-A.5.1-wrong-maturity

nc/NC-YYYY-NNN-descricao       → branch de trabalho para closure de NC
  ex: nc/2026-003-access-review-procedure

hotfix/CTRL-ID-urgente         → correcção urgente pós-auditoria
  → vai directamente para main via PR com review obrigatório
```

### 6.3 Tags de auditoria

```
audit/2025-internal-q1         → snapshot do momento da auditoria interna Q1 2025
audit/2025-external-cert       → snapshot da auditoria externa de certificação 2025
audit/2026-internal-q1         → etc.
management-review/2025-q4      → snapshot do management review Q4 2025
```

Tags permitem `git diff audit/2025-external-cert audit/2026-internal-q1` para
ver exactamente o que mudou entre dois momentos de auditoria.

### 6.4 Convenção de commits

```
Tipos (Conventional Commits):
  feat:     novo controlo ou nova evidência
  fix:      correcção de dados (maturity incorrecta, ref errada)
  docs:     actualização de README, scope, audit plan
  nc:       relacionado com NC/OFI
  accept:   aceitação de risco
  audit:    artefactos de auditoria (scope, report)
  chore:    manutenção (update SoA source, snapshot)

Formato:
  <tipo>(CTRL-ID|NC-NNN|framework): <descrição imperativa em inglês>

Exemplos:
  feat(CTRL-A.8.8): add wardex CI gate as pipeline evidence
  fix(CTRL-A.5.1): correct maturity from 3 to 4 — MFA now fully implemented
  nc(NC-2026-003): close access review NC — procedure approved by CISO
  audit(iso27001): add internal Q1 2026 audit scope and plan
  accept(CVE-2024-1234): 7-day risk acceptance pending auth-lib upgrade
  chore: update iso27001-soa-v3.xlsx from latest GRC review
```

### 6.5 Pull Request templates

**`control-update.md`** — para qualquer PR que toque em `controls/`:

```markdown
## Control Update

**Control ID(s):** CTRL-A.X.X
**Framework:** iso27001 / iso22301 / iso9001
**Change type:** [ ] New control [ ] Maturity update [ ] Evidence update [ ] Correction

### What changed and why
<!-- Describe the change. Reference the policy, system, or audit finding that motivated it -->

### Evidence of implementation
<!-- If maturity increased, what evidence exists? Reference it in the YAML -->

### Wardex gap report before/after
<!-- Paste the relevant Finding from wardex output before and after this change -->
```diff
- status: gap    → CTRL-A.8.8  score: 7.2
+ status: covered → CTRL-A.8.8  score: 7.2
```

### Reviewer checklist
- [ ] Control ID matches ISO 27001:2022 Annex A exactly
- [ ] Maturity level is justified by evidence references
- [ ] Evidence references are reachable and current
- [ ] context_weight change (if any) is explained in weight_justification
- [ ] `wardex --framework iso27001 controls/**/*.yaml` runs without errors
```

**`nc-closure.md`** — para PRs de closure de NC/OFI:

```markdown
## NC/OFI Closure

**NC/OFI ID:** NC-2026-NNN
**Source:** [ ] Internal audit [ ] External audit [ ] Management review
**Type:** [ ] Non-Conformity [ ] Opportunity for Improvement

### Root cause
<!-- What caused the NC? -->

### Corrective action implemented
<!-- What was done? Reference commits, tickets, or documents -->

### Evidence of closure
<!-- What proves the NC is resolved? -->

### CTRL updates in this PR
<!-- List any controls.yaml changes that demonstrate closure -->

### Wardex verification
<!-- wardex --framework iso27001 output showing the gap is now covered -->

### Approver
<!-- NC closure requires GRC owner sign-off -->
- [ ] Reviewed and approved by: @CISO / @GRC-owner
```

---

## 7. Ciclo de comunicação por fase

### 7.1 Calendário de auditoria — 12 semanas

```
SEMANA -12  Kick-off de preparação
SEMANA -10  Branch audit/YYYY-TYPE criada
SEMANA  -8  Wardex pre-audit run → relatório de gaps
SEMANA  -6  Gap remediation sprint
SEMANA  -4  Wardex validation run + freeze de controlos
SEMANA  -2  Entrega de documentação ao auditor
SEMANA   0  Auditoria (on-site ou remota)
SEMANA  +1  Relatório de auditoria recebido
SEMANA  +2  NCs abertas no repositório
SEMANA  +4  Planos de acção aprovados
SEMANA  +12 Follow-up de NCs (90 dias standard)
```

### 7.2 Comunicações por fase

**Semana -12: Kick-off**

```markdown
Destinatários: CISO, Engineering Leads, Compliance Officer, Management
Canal: Email + reunião de kick-off
Assunto: [IMS Audit 2026] Preparação iniciada — acções necessárias

Conteúdo obrigatório:
  - Data da auditoria confirmada
  - Scope da auditoria (frameworks, entidades)
  - Link para branch audit/2026-TYPE no repositório IMS
  - Assignees por domínio de controlos
  - Data limite para actualizações de evidências (Semana -4)
  - Link para último relatório Wardex (estado actual de gaps)

Artefacto Wardex anexo:
  wardex-report.json (run do dia, todos os frameworks)
  Highlight: cobertura actual vs. auditoria anterior (delta)
```

**Semana -8: Gap Report**

```markdown
Destinatários: Control owners (por domínio), CISO
Canal: Email automatizado + ticket Jira por gap crítico
Assunto: [IMS Audit 2026] Gap analysis — 8 semanas para auditoria

Script de geração:
  wardex --framework iso27001 controls/iso27001/**/*.yaml \
    --output json --out-file reports/gap-iso27001-$(date +%Y%m%d).json
  wardex --framework iso22301 controls/iso22301/**/*.yaml \
    --output markdown --out-file reports/gap-iso22301-$(date +%Y%m%d).md

Conteúdo obrigatório:
  - Coverage % por framework (vs. auditoria anterior)
  - Top 10 gaps por score (roadmap prioritizado)
  - Controlos com maturity < 3 (risco alto para auditoria)
  - Aceitações de risco a expirar antes da auditoria
  - Assignee por gap crítico (derivado de weight_justification/owner)
```

**Semana -4: Freeze e validação**

```markdown
Destinatários: Todo o IMS team
Canal: Email + PR obrigatório de freeze
Assunto: [IMS Audit 2026] FREEZE — sem alterações de controlos após hoje

Acção técnica:
  git tag pre-audit/2026-TYPE
  git checkout -b audit/2026-TYPE
  # Branch protegida: só hotfix permitido após este ponto

Validação final Wardex:
  wardex --framework iso27001 controls/iso27001/**/*.yaml --output markdown
  wardex --framework iso22301 controls/iso22301/**/*.yaml --output markdown
  wardex --framework iso9001   controls/iso9001/**/*.yaml  --output markdown

  # Guardar os 3 relatórios no repositório
  cp reports/gap-*.md audits/2026/external-cert/pre-audit-reports/
  git commit -m "audit(all): pre-audit gap reports — freeze point"
  git push origin audit/2026-TYPE
```

**Semana 0: Auditoria**

```markdown
Destinatários: Auditor externo / Equipa interna de auditoria
Canal: Partilha directa de artefactos

Artefactos Wardex a disponibilizar:
  1. controls/*.yaml — declaração de todos os controlos (fonte primária)
  2. wardex-report.json (run do dia da auditoria) — estado actual
  3. wardex-accept-audit.log — audit trail de aceitações de risco
  4. wardex-acceptances.yaml — aceitações activas com HMAC
  5. Snapshot delta vs. auditoria anterior — evolução documentada

Comando de run no dia:
  wardex --framework iso27001 \
    --snapshot-file snapshots/.wardex_snapshot_iso27001.json \
    --output json --out-file audits/2026/external-cert/wardex-audit-day.json \
    controls/iso27001/**/*.yaml

  git add audits/2026/external-cert/wardex-audit-day.json
  git commit -m "audit(iso27001): day-of-audit snapshot — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  git tag audit/2026-external-cert
  git push origin audit/2026-external-cert --tags
```

**Semana +2: Abertura de NCs**

```markdown
Destinatários: Control owners das NCs, CISO, Management
Canal: Email por NC + branch nc/YYYY-NNN

Por cada NC:
  git checkout -b nc/2026-NNN-descricao develop
