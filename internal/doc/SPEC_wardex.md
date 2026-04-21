# Spec Técnica — Wardex
**warden · index**
**Gap Analysis, Risk-Based Release Gate e Business Impact — CLI Tool em Go**

---

## 1. Visão Geral

Ferramenta de linha de comando em Go que ingere controles de segurança já implementados
(ISO 22301, ISO 9001, QNRCS, ou frameworks proprietários) em formato YAML, JSON ou CSV,
correlaciona-os com os 93 controles da Annex A da ISO 27001:2022, e produz um relatório
de gap analysis com scoring de maturidade, priorização de riscos orientada ao impacto
no negócio, e um mecanismo de decisão de release baseado em risco composto — não em
threshold binário de CVSS.

**Objetivo central:** tornar visível, de forma automática e auditável, o delta entre o
estado atual de conformidade de uma organização e os requisitos da ISO 27001 — com
priorização baseada em criticidade técnica ajustada ao contexto do negócio, e com uma
decisão de release que considera vulnerabilidade, exposição, criticidade do asset e
controles compensatórios.

**Premissa de design:** a ferramenta conhece apenas a ISO 27001. Não assume conhecimento
prévio dos frameworks de entrada. A correlação é feita por inferência semântica e
declaração explícita do operador.

**Premissa sobre gates de segurança:** gates binários baseados em CVSS threshold produzem
dois tipos de falha igualmente graves — falsos positivos que criam pressão para desligar
o scanner, e falsos negativos quando o threshold é elevado para reduzir ruído. O modelo
correto é um risk score composto que reflecte a vulnerabilidade no contexto real do sistema.

---

## 2. Requisitos Funcionais

### RF-01 — Ingestion de Controles Existentes

- Lê arquivos de controles implementados nos formatos:
  - **YAML** (formato nativo, recomendado)
  - **JSON** (compatível com exports de ferramentas GRC)
  - **CSV** (compatível com exports de Excel / planilhas de auditoria)
- Cada entrada deve conter no mínimo: `id`, `name`, `maturity` (1–5).
- Campos opcionais: `framework`, `domains[]`, `evidences[]`, `context_weight`, `weight_justification`.
- Entradas com campos obrigatórios ausentes são rejeitadas com erro descritivo.
- Suporte a múltiplos arquivos de entrada na mesma execução (merge automático).

### RF-02 — Correlation Engine

- Para cada controle da Annex A da ISO 27001:2022, o catálogo interno define:
  - `domains[]`: temas semânticos cobertos (ex: `access_control`, `incident_response`)
  - `keywords[]`: termos relevantes para matching textual
  - `evidence_types[]`: tipos de evidência aceitos (ex: `policy`, `test_result`, `log`)
  - `base_score`: criticidade base de 0.0 a 10.0 ancorada em referências CVSS/FAIR
  - `practices[]`: práticas concretas que cobrem o controle, cada uma com maturidade esperada
- Correlação opera em dois modos:
  - **Declarativo:** o controle de entrada declara explicitamente `domains[]` — sinal forte
  - **Inferido:** matching por `keywords[]` contra `name` e `description` do controle — sinal fraco
- Um controle de entrada pode cobrir múltiplos controles da Annex A.
- Um controle da Annex A pode ser coberto por múltiplos controles de entrada.
- Cada correlação recebe um `confidence` score: `high` (declarativo) ou `low` (inferido).

### RF-03 — Gap Analysis

- Classifica cada um dos 93 controles da Annex A em três estados:

  | Estado     | Critério                                                                         |
  |------------|----------------------------------------------------------------------------------|
  | `covered`  | ≥1 correlação com `confidence: high` e maturidade ≥ 3 e evidência declarada     |
  | `partial`  | correlação existe mas maturidade < 3, ou sem evidência, ou só `confidence: low`  |
  | `gap`      | nenhuma correlação encontrada                                                    |

- Para controles em estado `partial`, a saída inclui o motivo específico da cobertura incompleta.
- Resultado exportável como estrutura de dados completa (JSON) para integração downstream.

### RF-04 — Maturity Scoring

- Calcula score de maturidade por domínio da ISO 27001:2022:
  - **Organizational controls** (A.5) — 37 controles
  - **People controls** (A.6) — 8 controles
  - **Physical controls** (A.7) — 14 controles
  - **Technological controls** (A.8) — 34 controles
- Score por domínio: média ponderada da maturidade dos controles cobertos / total do domínio.
- Score global de conformidade: percentagem de controles `covered` sobre 93.
- A maturidade da prática de release gate (RF-06) contribui explicitamente para o score
  do domínio tecnológico, tornando visível o nível de sofisticação do gate.

### RF-05 — Risk Scoring e Priorização com Impacto no Negócio

- O score final de cada gap é calculado como:

  ```
  final_score = base_score × context_weight
  ```

  Onde:
  - `base_score` ∈ [0.0, 10.0] — definido no catálogo interno, ancorado em CVSS v3.1
    e, quando aplicável, em métricas FAIR (frequência de perda e magnitude).
  - `context_weight` ∈ [0.5, 2.0] — multiplicador declarado pela organização no arquivo
    de configuração. Default: `1.0`.

- O arquivo de configuração suporta pesos por controle individual ou por domínio inteiro.
- Peso deve ser acompanhado de `weight_justification` (texto livre) para rastreabilidade auditável.
- O relatório de priorização ordena os gaps por `final_score` decrescente.
- A ausência de `context_weight` não bloqueia a execução — a lib opera com base_score puro.

### RF-06 — Risk-Based Release Gate

Esta é a feature central da ferramenta para contextos de pipeline CI/CD. Substitui o
paradigma de gate binário (CVSS ≥ threshold → BLOCK) por uma decisão de release baseada
em risco composto, contextualizado ao asset e ao ambiente.

#### RF-06.1 — Modelo de Decisão

O risco de release $R(v, \alpha)$ é um modelo composto que purifica a gravidade técnica através do contexto organizacional:

$$R(v, \alpha) = CVSS(v) \times EPSS(v) \times C(\alpha) \times E(\alpha) \times (1 - \Phi(\alpha))$$

Onde:
- $CVSS(v)$ — Score base NVD (obrigatório).
- $EPSS(v)$ — Probabilidade de exploração (FIRST.org). Assume `1.0` (fail-close) se ausente.
- $C(\alpha)$ — Criticidade: `1.5` (BANK/INFRA), `1.0` (Standard), `0.75` (Low).
- $E(\alpha)$ — Exposição: `1.5` (Extrema/High), `1.0` (Standard/Internet), `0.5` (Reduzida/OT).
- $(1 - \Phi(\alpha))$ — Factor de mitigação por controlos compensatórios (clamped em `0.2`).

O resultado `release_risk` é comparado com `release_risk_appetite` declarado pela
organização. Se `release_risk > release_risk_appetite` → gate bloqueia com justificativa
detalhada. Caso contrário → gate libera, mas o score é visível no artefacto de release.

#### RF-06.2 — Maturidade do Gate em si

O próprio gate de release é tratado como uma **prática** do controle `A.8.8` (gestão de
vulnerabilidades técnicas), com nível de maturidade mensurável e inferido automaticamente:

| Nível | Descrição                                                                              |
|-------|----------------------------------------------------------------------------------------|
| 1     | Gate binário por CVSS threshold fixo. Não considera contexto.                          |
| 2     | Threshold ajustável por projeto, mas ainda binário e sem contexto de exposição.        |
| 3     | Considera criticidade do asset e perfil de exposição de rede.                          |
| 4     | Incorpora controles compensatórios na decisão. Reduz falsos positivos.                 |
| 5     | Modelo de risco composto com CVSS + EPSS + asset_criticality + compensating_controls.  |

A ferramenta detecta automaticamente o nível com base nos campos declarados no
`asset_context`. Quanto mais campos preenchidos, maior o nível inferido. Esse nível
alimenta o maturity score do domínio tecnológico (A.8).

#### RF-06.3 — Transparência da Decisão

Toda decisão de gate (block ou allow) é acompanhada de um breakdown auditável:

```
[BLOCK] CVE-2024-1234 — release_risk: 8.7 > appetite: 6.0
  ├── cvss_base:               9.1
  ├── epss_factor:             0.84  (alta probabilidade de exploração)
  ├── asset_criticality:       0.9   (sistema de pagamento — impacto crítico)
  ├── exposure_factor:         0.95  (internet-facing, autenticação presente)
  ├── compensating_controls:   0.15  (WAF efetividade 0.15 para este vetor)
  └── release_risk:            8.7

[ALLOW] CVE-2024-5678 — release_risk: 3.2 ≤ appetite: 6.0
  ├── cvss_base:               7.5
  ├── epss_factor:             0.12  (baixa probabilidade de exploração)
  ├── asset_criticality:       0.4   (ferramenta interna)
  ├── exposure_factor:         0.3   (air-gapped, sem exposição externa)
  ├── compensating_controls:   0.60  (network segmentation + runtime protection)
  └── release_risk:            3.2
```

Este breakdown é exportado como parte do relatório JSON e exibido no terminal com
cores (vermelho para BLOCK, verde para ALLOW, amarelo para zona de atenção).

#### RF-06.4 — Múltiplas Vulnerabilidades

Quando múltiplos CVEs são avaliados num mesmo release:
- O gate bloqueia se **qualquer** CVE superar o `release_risk_appetite` (modo `any`, default).
- Flag `--gate-mode aggregate` bloqueia se a soma dos scores superar um threshold separado.
- O relatório lista todos os CVEs avaliados, ordenados por release_risk decrescente.

### RF-07 — Delta Tracking

- A lib persiste snapshots do estado de cobertura em arquivo local (`.wardex_snapshot.json`).
- Em execuções subsequentes, compara o estado atual com o snapshot anterior.
- O relatório inclui uma secção de delta mostrando:
  - Gaps fechados desde a última execução
  - Gaps novos ou regressões
  - Variação do score global de conformidade (ex: `+4.3%`)
  - Evolução do nível de maturidade do release gate entre execuções
- Flag `--no-snapshot` desativa persistência para execuções one-shot (ex: CI/CD).

### RF-08 — Report Generation

- Três formatos de saída configuráveis via flag `--output`:

  | Formato    | Uso esperado                                          |
  |------------|-------------------------------------------------------|
  | `markdown` | Documentação, pull requests, wikis                    |
  | `json`     | Integração com pipelines, dashboards, ferramentas GRC |
  | `csv`      | Auditores, Excel, ferramentas de gestão de risco      |

- Estrutura do relatório:
  1. **Sumário Executivo** — score global, cobertura por domínio, top 5 gaps críticos, decisão do gate
  2. **Gap Analysis Detalhado** — todos os controles com estado, justificativa e evidências
  3. **Release Gate Report** — decisões por CVE com breakdown completo (se `--gate` ativo)
  4. **Roadmap Priorizado** — lista ordenada por `final_score` com ação recomendada
  5. **Delta** — variação desde a última execução (omitido se `--no-snapshot`)

- O sumário executivo é desenhado para apresentação direta em management reviews.

---

## 3. Requisitos Não Funcionais

- **Linguagem:** Go 1.22+
- **Zero dependências externas para lógica de negócio** — stdlib pura para correlation engine, scoring, gap analysis e release gate
- **Dependências externas** permitidas apenas para I/O: parsing YAML (`gopkg.in/yaml.v3`), CLI (`github.com/spf13/cobra`), terminal colorido (`github.com/charmbracelet/lipgloss`)
- **Testável:** cobertura obrigatória em `pkg/catalog`, `pkg/correlator`, `pkg/scorer`, `pkg/releasegate`
- **Determinístico:** a mesma entrada produz sempre o mesmo output
- **Auditável:** toda decisão — cobertura, gap ou release — é acompanhada de justificativa textual e breakdown numérico
- **Portátil:** binário único, sem dependência de runtime, base de dados ou serviços externos
- **CI/CD-friendly:** exit codes distintos para compliance gap (`11`) e release bloqueado (`10`)

---

## 4. Arquitetura de Pacotes

```
wardex/
├── main.go                        # Entry point, flags CLI, orquestração
├── go.mod
├── go.sum
│
├── pkg/
│   ├── model/
│   │   ├── control.go             # ExistingControl, AnnexAControl, Mapping, Evidence, Practice
│   │   ├── release.go             # Vulnerability, AssetContext, CompensatingControl,
│   │   │                          # ReleaseDecision, RiskBreakdown, GateReport
│   │   └── report.go              # GapReport, ExecutiveSummary, Finding, Delta,
│   │                              # GatePracticeStatus
│   │
│   ├── catalog/
│   │   ├── catalog.go             # Carrega e expõe os 93 controles com práticas e metadados
│   │   ├── annex_a.yaml           # Fonte de dados embutida (embed.FS)
│   │   └── catalog_test.go
│   │
│   ├── ingestion/
│   │   ├── ingestion.go           # Dispatcher: detecta formato e delega
│   │   ├── yaml_reader.go
│   │   ├── json_reader.go
│   │   ├── csv_reader.go
│   │   └── ingestion_test.go
│   │
│   ├── correlator/
│   │   ├── correlator.go          # Motor de correlação: declarativa + inferida
│   │   ├── matcher.go             # Keyword matching e domain matching
│   │   └── correlator_test.go
│   │
│   ├── scorer/
│   │   ├── scorer.go              # final_score = base_score × context_weight
│   │   ├── maturity.go            # Score de maturidade por domínio + gate maturity
│   │   └── scorer_test.go
│   │
│   ├── analyzer/
│   │   ├── analyzer.go            # Estado: covered / partial / gap
│   │   ├── gap.go                 # Justificativas de cobertura parcial
│   │   └── analyzer_test.go
│   │
│   ├── releasegate/
│   │   ├── gate.go                # Orquestrador: avalia CVEs, decide block/allow
│   │   ├── scorer.go              # Modelo de risco composto: fórmula release_risk
│   │   ├── maturity.go            # Infere nível de maturidade do gate (1–5)
│   │   ├── breakdown.go           # Gera breakdown auditável por decisão
│   │   └── gate_test.go
│   │
│   ├── snapshot/
│   │   ├── snapshot.go            # Persistência e leitura de snapshots locais
│   │   ├── delta.go               # Cálculo de variações entre execuções
│   │   └── snapshot_test.go
│   │
│   └── report/
│       ├── report.go              # Orquestrador de relatório
│       ├── markdown.go
│       ├── json.go
│       ├── csv.go
│       └── report_test.go
│
├── config/
│   └── config.go                  # Leitura de wardex-config.yaml
│
└── README.md
```

---

## 5. Modelo de Dados Central

```go
// pkg/model/control.go

// ExistingControl representa um controle já implementado na organização.
type ExistingControl struct {
    ID                  string
    Name                string
    Description         string     // Usado no matching inferido
    Framework           string     // Informativo
    Domains             []string   // Temas semânticos declarados
    Maturity            int        // 1 (inicial) a 5 (otimizado)
    Evidences           []Evidence
    ContextWeight       float64    // Multiplicador de risco (default: 1.0)
    WeightJustification string     // Justificativa auditável
}

// AnnexAControl representa um controle da ISO 27001:2022 Annex A.
type AnnexAControl struct {
    ID            string
    Name          string
    Domain        string     // "organizational" | "people" | "physical" | "technological"
    Domains       []string
    Keywords      []string
    EvidenceTypes []string
    BaseScore     float64    // Criticidade base 0.0–10.0
    Practices     []Practice // Práticas concretas que cobrem o controle
}

// Practice representa uma prática concreta associada a um controle Annex A.
// Para A.8.8: SCA scanner, release gate policy, SBOM generation.
type Practice struct {
    ID           string
    Name         string
    MinMaturity  int    // Maturidade mínima para cobertura válida
    GateRelevant bool   // true se esta prática corresponde a um release gate
}

// Evidence representa uma evidência declarada.
type Evidence struct {
    Type string // "policy" | "procedure" | "test_result" | "log" | "certificate" | "document"
    Ref  string
}

// Mapping representa a correlação entre um controle existente e um controle da Annex A.
type Mapping struct {
    ExistingControlID string
    AnnexAControlID   string
    Confidence        string   // "high" | "low"
    MatchedDomains    []string
    MatchedKeywords   []string
}
```

```go
// pkg/model/release.go

// Vulnerability representa uma vulnerabilidade a ser avaliada pelo release gate.
type Vulnerability struct {
    CVEID      string
    CVSSBase   float64  // CVSS v3.1 base score (obrigatório)
    EPSSScore  float64  // Probabilidade EPSS (opcional; default 1.0)
    Component  string   // Componente afetado (informativo)
    Reachable  bool     // false reduz exposure_factor automaticamente
}

// AssetContext descreve o contexto do asset.
// Cada campo preenchido aumenta o nível de maturidade do gate inferido.
type AssetContext struct {
    Criticality    float64  // 0.0–1.0: impacto de negócio se comprometido
    InternetFacing bool
    RequiresAuth   bool     // Reduz exposure em 0.2 quando true
    DataClass      string   // "public" | "internal" | "confidential" | "restricted"
    Environment    string   // "production" | "staging" | "development"
}

// CompensatingControl representa um controle que reduz exploitabilidade.
type CompensatingControl struct {
    Type          string   // "waf" | "network_segmentation" | "runtime_protection" | "ids"
    Effectiveness float64  // 0.0–0.8: fração de redução de risco aplicada
    Justification string
}

// RiskBreakdown expõe cada componente do cálculo para rastreabilidade.
type RiskBreakdown struct {
    CVSSBase             float64
    EPSSFactor           float64
    AdjustedScore        float64
    AssetCriticality     float64
    ExposureFactor       float64
    CompensatingEffect   float64  // Efetividade combinada, clamped em 0.8
    FinalReleaseRisk     float64
}

// ReleaseDecision representa o resultado da avaliação de uma vulnerabilidade.
type ReleaseDecision struct {
    Vulnerability Vulnerability
    ReleaseRisk   float64
    RiskAppetite  float64
    Decision      string        // "block" | "allow" | "warn"
    Breakdown     RiskBreakdown
    AuditTrail    string        // Texto legível para auditoria
}

// GateReport agrega todas as decisões para um conjunto de vulnerabilidades.
type GateReport struct {
    OverallDecision   string            // "block" | "allow"
    GateMaturityLevel int               // 1–5, inferido dos campos preenchidos
    Decisions         []ReleaseDecision
    BlockedCount      int
    AllowedCount      int
    HighestRisk       float64
}
```

```go
// pkg/model/report.go

type CoverageStatus string

const (
    StatusCovered CoverageStatus = "covered"
    StatusPartial CoverageStatus = "partial"
    StatusGap     CoverageStatus = "gap"
)

// GatePracticeStatus resume o estado da prática de release gate para um controle.
type GatePracticeStatus struct {
    PracticeID    string
    MaturityLevel int    // nível inferido do AssetContext declarado
    MaturityLabel string // descrição humana do nível
    IsConfigured  bool
}

// Finding representa o resultado da análise de um controle da Annex A.
type Finding struct {
    Control        AnnexAControl
    Status         CoverageStatus
    FinalScore     float64
    CoveredBy      []Mapping
    GapReasons     []string
    Recommendation string
    GatePractice   *GatePracticeStatus // não-nil se o controle tem práticas de gate
}

// DomainSummary resume a cobertura e maturidade de um domínio.
type DomainSummary struct {
    Domain          string
    TotalControls   int
    CoveredCount    int
    PartialCount    int
    GapCount        int
    MaturityScore   float64
    CoveragePercent float64
}

// ExecutiveSummary é desenhado para management reviews.
type ExecutiveSummary struct {
    GeneratedAt     time.Time
    TotalControls   int
    CoveredCount    int
    PartialCount    int
    GapCount        int
    GlobalCoverage  float64
    DomainSummaries []DomainSummary
    TopCriticalGaps []Finding
    GateSummary     *GateReport  // nil se --gate não foi ativado
}

// Delta representa a variação entre a execução atual e o snapshot anterior.
type Delta struct {
    SnapshotDate       time.Time
    CoverageChange     float64
    NewlyCovered       []string
    NewGaps            []string
    Unchanged          int
    GateMaturityChange int  // variação do nível de maturidade do gate
}

// GapReport é o relatório completo.
type GapReport struct {
    Summary  ExecutiveSummary
    Findings []Finding
    Roadmap  []Finding    // Subset de gaps/partials, ordenado por FinalScore desc
    Gate     *GateReport
    Delta    *Delta
}
```

---

## 6. Interface dos Packages Principais

```go
// pkg/ingestion/ingestion.go
func Load(path string) ([]model.ExistingControl, error)
func LoadMany(paths []string) ([]model.ExistingControl, error)

// pkg/correlator/correlator.go
type Correlator struct { Catalog []model.AnnexAControl }
func (c *Correlator) Correlate(controls []model.ExistingControl) []model.Mapping

// pkg/scorer/scorer.go
func Score(annexControl model.AnnexAControl, mappings []model.Mapping,
    controls []model.ExistingControl) float64
func MaturityByDomain(findings []model.Finding) []model.DomainSummary

// pkg/analyzer/analyzer.go
type Analyzer struct {
    Catalog  []model.AnnexAControl
    Mappings []model.Mapping
    Controls []model.ExistingControl
}
func (a *Analyzer) Analyze() []model.Finding

// pkg/releasegate/gate.go

// Gate avalia um conjunto de vulnerabilidades contra o perfil de risco da organização.
type Gate struct {
    AssetContext         model.AssetContext
    CompensatingControls []model.CompensatingControl
    RiskAppetite         float64
    Mode                 string  // "any" | "aggregate"
}

// Evaluate avalia todas as vulnerabilidades e retorna o GateReport completo.
// Cada ReleaseDecision inclui o breakdown auditável e o audit trail em texto.
func (g *Gate) Evaluate(vulns []model.Vulnerability) model.GateReport

// InferMaturityLevel retorna o nível de maturidade do gate (1–5) com base nos
// campos preenchidos no AssetContext e CompensatingControls.
func InferMaturityLevel(ctx model.AssetContext, controls []model.CompensatingControl) int

// pkg/snapshot/snapshot.go
func Save(report model.GapReport) error
func Load() (*model.GapReport, error)
func Diff(current, previous model.GapReport) model.Delta
```

---

## 7. Fluxo de Execução

```
[arquivo(s) de entrada YAML/JSON/CSV]         [vulnerabilities.yaml (opcional)]
         │                                               │
         ▼ pkg/ingestion                                 ▼ pkg/ingestion
[[]ExistingControl]                           [[]Vulnerability]
         │                                               │
         ▼ pkg/correlator                                ▼ pkg/releasegate
[[]Mapping — high/low confidence]             [GateReport — block/allow + breakdown]
         │                                               │
         ▼ pkg/scorer                                    │
[final_score por controle Annex A]                       │
         │                                               │
         ▼ pkg/analyzer                                  │
[[]Finding — covered/partial/gap]                        │
         │                                               │
         ├──▶ pkg/snapshot → Delta                       │
         │                                               │
         ▼ pkg/report ◀──────────────────────────────────┘
[GapReport → Markdown / JSON / CSV]
         │
         ▼
exit code:
  0 → tudo dentro do apetite de risco
  1 → gap de compliance crítico acima de --fail-above
  2 → release gate bloqueado (release_risk > risk_appetite)
```

---

## 8. Arquivo de Configuração da Organização

```yaml
# wardex-config.yaml

organization:
  name: "Exemplo Empresa SA"
  sector: "financial_services"
  scope: "ISMS perimeter - core banking systems"

# Pesos contextuais por domínio
domain_weights:
  technological: 1.8
  organizational: 1.2
  people: 1.0
  physical: 0.7

# Overrides por controle específico (precedência sobre domain_weights)
control_weights:
  "A.8.8":
    weight: 2.0
    justification: "PCI-DSS scope — gestão de vulnerabilidades é controle crítico"
  "A.5.23":
    weight: 1.5
    justification: "Dependência de cloud providers — risco top-5"

# Configuração do release gate (ativa RF-06 quando presente)
release_gate:
  enabled: true
  mode: "any"           # "any": bloqueia se qualquer CVE superar appetite
                        # "aggregate": bloqueia se soma dos scores superar aggregate_limit
  risk_appetite: 6.0
  aggregate_limit: 15.0 # relevante apenas em mode: aggregate

  asset_context:
    criticality: 0.9
    internet_facing: true
    requires_auth: true
    data_classification: "confidential"
    environment: "production"

  compensating_controls:
    - type: "waf"
      effectiveness: 0.35
      justification: "ModSecurity com ruleset OWASP CRS"
    - type: "network_segmentation"
      effectiveness: 0.25
      justification: "VPC isolada com security groups restritivos"
    - type: "runtime_protection"
      effectiveness: 0.20
      justification: "Falco com políticas customizadas"

# Thresholds para CI/CD (compliance gate)
thresholds:
  fail_above: 8.5
  warn_above: 6.0
```

---

## 9. Exemplo de Arquivo de Vulnerabilidades (Release Gate)

```yaml
# vulnerabilities.yaml — gerado por Trivy, Grype, ou preenchido manualmente
vulnerabilities:
  - cve_id: "CVE-2024-1234"
    cvss_base: 9.1
    epss_score: 0.84
    component: "com.example:auth-lib:2.1.0"
    reachable: true

  - cve_id: "CVE-2024-5678"
    cvss_base: 7.5
    epss_score: 0.12
    component: "org.example:util-lib:1.0.3"
    reachable: false    # componente não alcançável em runtime — reduz exposure

  - cve_id: "CVE-2024-9999"
    cvss_base: 5.3
    epss_score: 0.03
    component: "org.example:log-lib:3.2.1"
    reachable: true
```

---

## 10. Testes

### Unitários obrigatórios

| Ficheiro               | O que testar                                                                                      |
|------------------------|---------------------------------------------------------------------------------------------------|
| `ingestion_test.go`    | Parse correto YAML/JSON/CSV; erro em campos obrigatórios ausentes; merge sem duplicatas           |
| `catalog_test.go`      | 93 controles carregados; base_scores ∈ [0,10]; práticas com GateRelevant corretas em A.8.8       |
| `correlator_test.go`   | Declarativo → `high`; keyword → `low`; sem domínio não gera falsa cobertura                      |
| `scorer_test.go`       | `final_score = base_score` quando `weight = 1.0`; clamping fora de [0.5, 2.0]                    |
| `analyzer_test.go`     | Maturidade ≥ 3 + evidência → `covered`; sem evidência → `partial`; sem correlação → `gap`        |
| `gate_test.go`         | BLOCK quando release_risk > appetite; ALLOW quando ≤; reachable=false reduz exposure; compensating_controls reduzem score; clamping de compensating_effectiveness em 0.8; InferMaturityLevel cresce com campos preenchidos |
| `snapshot_test.go`     | Delta correto entre dois estados; Load nil na primeira execução; GateMaturityChange calculado     |
| `report_test.go`       | Markdown contém gate report; JSON deserializável; CSV com header correto                          |

### Testes de regressão críticos

```go
// RF-06 — O mesmo CVE produz decisões opostas em contextos diferentes.
// Este teste é a prova central do argumento da dissertação:
// o risco não está na vulnerabilidade, está na vulnerabilidade no contexto.
func TestRiskBasedGateVsBinaryThreshold(t *testing.T) {
    vuln := model.Vulnerability{
        CVEID: "CVE-2024-1234", CVSSBase: 9.1, EPSSScore: 0.84, Reachable: true,
    }

    // Contexto de baixo risco: ferramenta interna, air-gapped, controles fortes
    lowRiskGate := releasegate.Gate{
        AssetContext: model.AssetContext{
            Criticality: 0.2, InternetFacing: false, RequiresAuth: true,
        },
        CompensatingControls: []model.CompensatingControl{
            {Type: "network_segmentation", Effectiveness: 0.7},
            {Type: "runtime_protection", Effectiveness: 0.5},
        },
        RiskAppetite: 6.0,
    }

    // Contexto de alto risco: sistema financeiro exposto, sem compensação
    highRiskGate := releasegate.Gate{
        AssetContext: model.AssetContext{
            Criticality: 0.9, InternetFacing: true, RequiresAuth: false,
        },
        CompensatingControls: []model.CompensatingControl{},
        RiskAppetite: 6.0,
    }

    lowReport  := lowRiskGate.Evaluate([]model.Vulnerability{vuln})
    highReport := highRiskGate.Evaluate([]model.Vulnerability{vuln})

    if lowReport.OverallDecision != "allow" {
        t.Errorf("esperado allow em contexto de baixo risco, got: %s", lowReport.OverallDecision)
    }
    if highReport.OverallDecision != "block" {
        t.Errorf("esperado block em contexto de alto risco, got: %s", highReport.OverallDecision)
    }
}

// Maturidade do gate cresce com campos declarados — InferMaturityLevel é monotónico.
func TestGateMaturityInference(t *testing.T) {
    cases := []struct {
        ctx      model.AssetContext
        controls []model.CompensatingControl
        minLevel int
    }{
        {model.AssetContext{Criticality: 0.5}, nil, 1},
        {model.AssetContext{Criticality: 0.5, InternetFacing: true}, nil, 2},
        {model.AssetContext{Criticality: 0.5, InternetFacing: true, RequiresAuth: true}, nil, 3},
        {
            model.AssetContext{Criticality: 0.9, InternetFacing: true, RequiresAuth: true},
            []model.CompensatingControl{{Type: "waf", Effectiveness: 0.3}},
            4,
        },
    }
    for _, tc := range cases {
        level := releasegate.InferMaturityLevel(tc.ctx, tc.controls)
        if level < tc.minLevel {
            t.Errorf("esperado nível ≥ %d, got %d", tc.minLevel, level)
        }
    }
}

// Upgrade de maturidade de controle fecha gap correspondente (regressão de compliance).
func TestMaturityUpgradeClosesGap(t *testing.T) {
    cat := catalog.Load()
    weak := []model.ExistingControl{{
        ID: "CTRL-001", Domains: []string{"access_control"}, Maturity: 2,
        Evidences: []model.Evidence{{Type: "policy", Ref: "AC-POL-001"}},
    }}
    strong := []model.ExistingControl{{
        ID: "CTRL-001", Domains: []string{"access_control"}, Maturity: 3,
        Evidences: []model.Evidence{{Type: "policy", Ref: "AC-POL-001"}},
    }}
    weakFindings  := analyzer.New(cat, correlator.New(cat).Correlate(weak), weak).Analyze()
    strongFindings := analyzer.New(cat, correlator.New(cat).Correlate(strong), strong).Analyze()

    if countByStatus(strongFindings, model.StatusPartial) >= countByStatus(weakFindings, model.StatusPartial) {
        t.Error("upgrade de maturidade não reduziu partials como esperado")
    }
}
```

---

## 11. Flags CLI

```
Usage: wardex [flags] <input-file(s)>

  --config        string   Caminho para wardex-config.yaml (default: ./wardex-config.yaml)
  --output        string   Formato de saída: markdown|json|csv (default: markdown)
  --out-file      string   Arquivo de saída (default: stdout)
  --gate          string   Arquivo de vulnerabilidades para avaliar o release gate
  --gate-mode     string   Modo de gate: any|aggregate (default: any)
  --fail-above    float    Exit code 1 se gap com final_score acima deste valor
  --no-snapshot            Não lê nem grava snapshot
  --min-confidence string  Confiança mínima para correlação: high|low (default: low)
  --verbose                Exibe detalhes do processo de correlação no stderr
```

---

## 12. Execução Esperada

```bash
# Instalar
git clone https://github.com/had-nu/wardex
cd wardex
go mod tidy
go build -o wardex ./...

# Ou directamente via go install
go install github.com/had-nu/wardex@latest

# Gap analysis básico
wardex controls.yaml

# Com configuração da organização
wardex --config wardex-config.yaml controls.yaml

# Com release gate — avalia CVEs no contexto da organização
wardex --config wardex-config.yaml --gate vulnerabilities.yaml controls.yaml

# Em pipeline CI/CD — exit 11 se gap crítico, exit 10 se gate bloqueia
wardex --no-snapshot --fail-above 8.5 --gate vuln-scan.yaml controls.yaml

# Saída JSON para integração com dashboard ou SIEM
wardex --output json --out-file report.json --gate vuln-scan.yaml controls.yaml

# Correr testes com race detector
go test ./... -race -count=1

# Cobertura
go test ./... -coverprofile=coverage.out && go tool cover -html=coverage.out
```

---

## 13. Exemplo de Output — Sumário Executivo (Markdown)

```markdown
# ISO 27001:2022 — Compliance & Release Gate Report
**Generated:** 2025-10-14 | **Organization:** Exemplo Empresa SA

---

## Executive Summary

| Metric                     | Value        |
|----------------------------|--------------|
| Global Compliance Coverage | 61.3%        |
| Controls Covered           | 57 / 93      |
| Controls Partial           | 14 / 93      |
| Controls Gap               | 22 / 93      |
| Coverage vs Last Run       | +4.3% ↑      |
| Release Gate Decision      | ⛔ BLOCK      |
| Gate Maturity Level        | 4 / 5        |

---

## Coverage by Domain

| Domain           | Covered | Partial | Gap | Maturity Avg |
|------------------|---------|---------|-----|--------------|
| Organizational   | 22/37   | 8       | 7   | 2.9          |
| Technological    | 18/34   | 4       | 12  | 2.4          |
| Physical         | 11/14   | 1       | 2   | 3.5          |
| People           | 6/8     | 1       | 1   | 3.1          |

---

## Release Gate — Decision Breakdown

| CVE            | CVSS | EPSS | Release Risk | Decision |
|----------------|------|------|--------------|----------|
| CVE-2024-1234  | 9.1  | 0.84 | **8.7**      | ⛔ BLOCK  |
| CVE-2024-5678  | 7.5  | 0.12 | 3.2          | ✅ ALLOW  |
| CVE-2024-9999  | 5.3  | 0.03 | 1.1          | ✅ ALLOW  |

**Risk Appetite:** 6.0 | **Gate Mode:** any | **Gate Maturity:** Level 4

> CVE-2024-1234 bloqueado: asset_criticality 0.9 × exposure 0.95 ×
> cvss_adjusted 7.6 (9.1×0.84) = 8.7, acima do apetite 6.0.
> Controles compensatórios presentes (WAF 0.35 + segmentação 0.25)
> insuficientes para reduzir abaixo do apetite declarado.

---

## Top 5 Critical Compliance Gaps

| Control | Name                          | Score | Reason                             |
|---------|-------------------------------|-------|------------------------------------|
| A.8.8   | Management of technical vuln. | 9.4   | Gate configurado em maturidade 2   |
| A.5.7   | Threat intelligence           | 8.1   | Correlação low confidence apenas   |
| A.8.16  | Monitoring activities         | 7.8   | Maturidade 1, sem evidência        |
| A.5.23  | Security of cloud services    | 7.5   | Partial — evidência ausente        |
| A.8.12  | Data leakage prevention       | 7.2   | Nenhuma correlação encontrada      |

---

## Roadmap (prioritized)
[... lista completa ordenada por score ...]
```

---

## 14. Dependências Externas

| Pacote                              | Versão   | Justificação                              |
|-------------------------------------|----------|-------------------------------------------|
| `gopkg.in/yaml.v3`                  | latest   | Parsing de YAML para ingestion e catálogo |
| `github.com/spf13/cobra`            | latest   | CLI estruturada com subcomandos e flags   |
| `github.com/charmbracelet/lipgloss` | latest   | Output colorido no terminal               |

Sem dependências externas em `pkg/catalog`, `pkg/correlator`, `pkg/scorer`,
`pkg/analyzer`, `pkg/releasegate`.

---

## 15. Notas de Implementação

**O problema do gate binário:** Um threshold CVSS fixo mede a severidade da vulnerabilidade,
não o risco real. O mesmo CVE 9.1 num componente de log interno air-gapped tem risco de
release radicalmente diferente do mesmo CVE num serviço de autenticação exposto à internet.
A lib formaliza esta distinção como modelo de dados de primeira classe — não como
configuração opcional ou feature secundária.

**EPSS como fator de probabilidade:** O CVSS mede o impacto potencial. O EPSS mede a
probabilidade de exploração nos próximos 30 dias. Um CVE com CVSS 9.1 e EPSS 0.03 é
substancialmente menos urgente do que CVSS 7.5 com EPSS 0.84. A lib suporta EPSS como
campo opcional — quando ausente, assume 1.0 (conservador por defeito). Isso permite adoção
gradual sem exigir integração imediata com feeds EPSS.

**Compensating controls com teto de efetividade:** A efetividade combinada é clamped em
0.8 — nenhuma combinação de controles compensatórios elimina o risco por completo. Isso
reflecte a realidade operacional e impede que configurações fictícias liberem CVEs críticos.
O teto é explícito no modelo e aparece no breakdown auditável.

**Maturidade do gate como métrica de compliance:** O nível 1–5 não é cosmético. Ele alimenta
directamente o maturity score do domínio tecnológico (A.8). Uma organização que evolui de
gate binário (nível 1) para risk-based completo (nível 5) vê essa evolução reflectida no
score global de conformidade da ISO 27001 — criando um incentivo mensurável e auditável para
adoptar o modelo correto. Este é o ponto de conexão directo com a dissertação: a maturidade
do modelo de decisão de release é um indicador de conformidade com A.8.8.

**Catálogo como dado embutido:** Os 93 controles com metadados ficam em `catalog/annex_a.yaml`
embutido via `embed.FS`. A qualidade dos `base_scores`, `domains`, `keywords` e especialmente
das `practices` com `GateRelevant: true` determina a utilidade de todo o output.

**Delta tracking como evidência de melhoria contínua:** A ISO 27001 cláusula 10.2 exige
evidência de melhoria contínua. O snapshot automático cria esse registo sem esforço adicional.
A evolução do `GateMaturityLevel` entre snapshots é prova concreta de maturação do programa
de segurança — exactamente o tipo de evidência que um auditor ISO quer ver.

**Exit codes como quality gates de pipeline:** Exit `0` (tudo dentro do apetite), `1` (gap
de compliance crítico), `2` (release bloqueado pelo gate) permitem que a pipeline tome
decisões autónomas sem parsing de output — o mesmo padrão de SAST e SCA, aplicado agora
também ao compliance contínuo.
