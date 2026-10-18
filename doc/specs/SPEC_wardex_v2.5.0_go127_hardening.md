# SPEC: Wardex v2.5.0 — Go 1.27 Migration & Codebase Hardening

**Status:** Draft  
**Author:** André Ataíde (had-nu)  
**Date:** 2026-08-20  
**Target Version:** v2.5.0  
**Go Version:** 1.27.0  
**Related:** `SPEC_wardex_v2.0_CRA_Art14.md`, `SPEC_wardex_v2.0.1_sdlc_hardening.md`

---

## 1. Resumo Executivo

Esta especificação define a migração do Wardex para Go 1.27 e a refatoração estrutural das oportunidades de melhoria identificadas na avaliação de qualidade de código (Q3 2026). O objectivo é manter a postura de segurança e conformidade do Wardex enquanto se reduz a dívida técnica de crescimento acumulada entre v1.0 e v2.4.

As alterações são classificadas em dois eixos:
- **Eixo A — Runtime & Tooling:** Migração para Go 1.27, modernização de CI, Docker, e linting.
- **Eixo B — Arquitectura & Hardening:** Refactor da orquestração CLI, centralização de I/O seguro, adoção de `log/slog`, propagação de `context.Context`, e reestruturação de `pkg/accept`.

---

## 2. Motivação

### 2.1. Porquê Go 1.27?

| Benefício | Impacto no Wardex | Ficheiros Afetados |
|-----------|-------------------|-------------------|
| Alocações especializadas por tamanho (≤80 B) | ↓ 30% custo de alloc em structs de domínio (`Vulnerability`, `Finding`, `ReleaseDecision`) | `pkg/model`, `pkg/releasegate`, `pkg/analyzer` |
| `encoding/json` v2 backend | ↓ latência no parsing de EPSS, Grype, state store | `pkg/epss`, `pkg/ingestion`, `pkg/statestore` |
| Auto-drenagem de `Response.Body` | Melhor reuse de conexões TCP na API EPSS (batched chunks) | `pkg/epss/client.go` |
| `runtime/pprof` — `goroutineleak` | Detecção de leaks nos testes de provenance gRPC | `pkg/provenance/*_test.go` |
| `go test` — `stdversion` vet | Prevenção de uso acidental de APIs stdlib demasiado recentes | Toda a base de código |
| `go fix` — modernizadores | Automatização de `atomictypes`, `embedlit`, `slicesbackward` | Toda a base de código |

### 2.2. Porquê Refactor Estrutural?

A análise de qualidade identificou padrões de crescimento que, se não corrigidos, aumentam o risco de regressões e dificultam o onboarding de contribuidores:

1. **`main.go` / `cmd/evaluate` como God Objects:** A lógica de orquestração do pipeline de avaliação está duplicada e acoplada a `os.Exit`, `os.Stderr`, e I/O de ficheiros. Isto torna o `evaluate` praticamente untestável unitariamente.
2. **Duplicação de `os.ReadFile` + `#nosec G304`:** O padrão repete-se em ~15 ficheiros. A centralização num `SafeReadFile` reduz a superfície de erro e simplifica auditorias de segurança.
3. **Ausência de `log/slog`:** O logging ad-hoc via `fmt.Fprintf(os.Stderr, ...)` impede filtragem por nível, integração com syslog centralizado, e correlação estruturada em SIEM.
4. **`pkg/accept` como monólito:** Contém lógica de aceitação de risco, verificação criptográfica, audit log, forwarding, e hash de config. A coesão é baixa e a reutilização é difícil.

---

## 3. Escopo

### 3.1. In-Scope

- Atualização de `go.mod` para `go 1.27.0`.
- Atualização de CI workflows (`.github/workflows/ci.yml`, `docker.yml`, `release.yml`).
- Atualização do `Dockerfile` e `go.mod` base image.
- Execução de `go fix ./...` e resolução de modernizações.
- Criação de `pkg/orchestrator` — extração da lógica de orquestração do `main.go` e `cmd/evaluate`.
- Criação de `pkg/cli/safefile.go` — centralização de `SafeReadFile` e `SafeWriteFile`.
- Migração de logging ad-hoc para `log/slog` em todos os packages `pkg/*` e `cmd/*`.
- Propagação de `context.Context` em `pkg/epss`, `pkg/provenance`, e `internal/notification`.
- Refactor de `pkg/accept` em sub-packages: `pkg/accept/store`, `pkg/accept/verify`, `pkg/accept/audit`.
- Substituição de sorting manual por `slices.SortFunc`.
- Fortalecimento de fuzz tests com invariantes de propriedade.

### 3.2. Out-of-Scope

- Alterações à lógica de cálculo de risco do `pkg/releasegate` (semântica inalterada).
- Alterações ao formato CBOR ou CDDL (backward compatibility preservada).
- Alterações ao protocolo 3CP ou Gleipnir.
- Novos frameworks de compliance (fora do scope desta SPEC).

---

## 4. Design Detalhado

### 4.1. Eixo A — Go 1.27 Migration

#### 4.1.1. `go.mod`

```go
module github.com/had-nu/wardex/v2

go 1.27.0

require (
    github.com/fxamacker/cbor/v2 v2.9.0
    github.com/had-nu/gleipnir v0.1.0
    github.com/spf13/cobra v1.10.2
    github.com/spf13/pflag v1.0.10
    google.golang.org/grpc v1.70.0
    gopkg.in/yaml.v3 v3.0.1
    lukechampine.com/blake3 v1.4.1
)
```

**Nota:** O `go mod tidy` fundirá blocos `require` duplicados na estrutura canónica de dois blocos (directas / indirectas), conforme comportamento do Go 1.27.

#### 4.1.2. CI Workflows

Atualizar `.github/workflows/ci.yml`:

```yaml
- name: Set up Go
  uses: actions/setup-go@v5
  with:
    go-version: '1.27.0'
```

Adicionar passo de `go fix` como gate:

```yaml
- name: Verify go fix is clean
  run: |
    go fix ./...
    git diff --exit-code || (echo "go fix produced changes. Run 'go fix ./...' locally." && exit 1)
```

#### 4.1.3. Dockerfile

```dockerfile
FROM golang:1.27-alpine AS builder
```

#### 4.1.4. `go fix` — Modernizações Esperadas

| Modernizador | Ocorrências Esperadas | Acção |
|--------------|----------------------|-------|
| `atomictypes` | 0 (não usamos `sync/atomic` com tipos genéricos) | N/A |
| `embedlit` | Possível em `pkg/report/templates/report.html` | Verificar se `//go:embed` pode ser simplificado |
| `slicesbackward` | 1 em `main.go` (sorting manual do roadmap) | Substituir por `slices.SortFunc` |
| `unsafefuncs` | 0 | N/A |

#### 4.1.5. Validação de `encoding/json` v2

**Risco:** O v2 altera o texto exacto de algumas mensagens de erro.  
**Mitigação:** Auditar todos os testes que fazem `assert.Contains(t, err.Error(), "...")` em erros JSON. Substituir por verificação de tipo (`errors.As`) ou por prefixo, nunca por string exacta.

---

### 4.2. Eixo B — Arquitectura & Hardening

#### 4.2.1. `pkg/orchestrator` — Extração da Orquestração

**Problema:** `main.go::runWardex` e `cmd/evaluate::runEvaluate` duplicam lógica de:
1. Carregamento de config + perfil.
2. Carregamento de controls + catálogo + correlação.
3. Filtragem de mappings por confiança.
4. Análise de gaps.
5. Avaliação do release gate.
6. Geração de snapshot.
7. Geração de report.
8. Decisão de exit code.

**Solução:** Criar `pkg/orchestrator/evaluation.go` com uma struct `EvaluationPipeline`:

```go
package orchestrator

type EvaluationPipeline struct {
    ConfigLoader     ConfigLoader
    CatalogLoader    CatalogLoader
    Correlator       *correlator.Correlator
    Analyzer         *analyzer.Analyzer
    Gate             *releasegate.Gate
    StateStore       *statestore.Store
    SnapshotManager  *snapshot.Manager
    ReportGenerator  report.Generator
    Logger           *slog.Logger
}

type EvaluationResult struct {
    Report      model.GapReport
    GateReport  *model.GateReport
    ExitReason  ExitReason
    ExitCode    int
}

func (p *EvaluationPipeline) Run(ctx context.Context, opts EvaluationOptions) (*EvaluationResult, error)
```

**Critérios:**
- `EvaluationPipeline` não chama `os.Exit`. Retorna `ExitCode` para o caller decidir.
- `EvaluationPipeline` não escreve directamente em `os.Stderr`. Usa `*slog.Logger`.
- `main.go` e `cmd/evaluate` ficam reduzidos a ~50 linhas: parse de flags, construção do pipeline, execução, e `os.Exit(result.ExitCode)`.

#### 4.2.2. `pkg/cli/safefile.go` — Centralização de I/O Seguro

```go
package cli

// SafeReadFile wraps os.ReadFile with path validation and centralizes #nosec G304.
func SafeReadFile(path string) ([]byte, error) {
    safePath, err := SafePath(path)
    if err != nil {
        return nil, fmt.Errorf("safe read: %w", err)
    }
    return os.ReadFile(safePath) // #nosec G304 — validated by SafePath
}

// SafeWriteFile wraps atomicwrite.Write with path validation.
func SafeWriteFile(path string, data []byte) error {
    safePath, err := SafeOutputPath(path)
    if err != nil {
        return fmt.Errorf("safe write: %w", err)
    }
    return atomicwrite.Write(safePath, data)
}
```

**Refactor:** Substituir todas as ocorrências de `os.ReadFile(safePathStr) // #nosec G304` por `cli.SafeReadFile(path)`.

#### 4.2.3. Migração para `log/slog`

**Estratégia:**
1. Adicionar `*slog.Logger` como dependência injectada nos serviços principais (`EvaluationPipeline`, `Store`, `EPSSClient`).
2. Criar `pkg/ui/logger.go` com helper para inicialização:

```go
func NewLogger(level slog.Level, useSyslog bool, endpoint string) *slog.Logger
```

3. Substituir padrões:

| Antigo | Novo |
|--------|------|
| `fmt.Fprintf(os.Stderr, "[INFO] ...\n")` | `logger.Info("...", "key", value)` |
| `fmt.Fprintf(os.Stderr, "[WARN] ...\n")` | `logger.Warn("...", "key", value)` |
| `fmt.Fprintf(os.Stderr, "[BLOCK] ...\n")` | `logger.Error("gate blocked", "cve", cve, "reason", reason)` |

**Nota:** O forwarding para syslog (`WARDEX_SYSLOG_ENDPOINT`) passa a ser implementado via `slog` Handler customizado ou via `syslog` package com formatação JSON, em vez de `pkg/accept/forward_syslog.go` ad-hoc.

#### 4.2.4. `context.Context` em Operações de Rede

**Packages a alterar:**

1. **`pkg/epss/client.go`:**
```go
func FetchScores(ctx context.Context, cves []string, logw io.Writer) (map[string]float64, map[string]string, error)
```
O `http.NewRequestWithContext(ctx, "GET", url, nil)` substitui `http.NewRequest`.

2. **`pkg/provenance/anchorer.go`:**
```go
type Anchorer interface {
    Submit(ctx context.Context, hash []byte, label string) (*AnchorResult, error)
    // ... todos os métodos já recebem context
}
```
A interface já declara `context.Context`. Verificar implementações (`embedded_gleipnir.go`, `grpc.go`, `noop.go`) para garantir que o context é propagado até ao `http.Client` ou `grpc.Dial`.

3. **`internal/notification/webhook.go`:**
```go
func SendWebhook(ctx context.Context, cfg WebhookConfig, payload []byte) error
```

#### 4.2.5. Refactor de `pkg/accept`

**Decomposição em sub-packages:**

```
pkg/accept/
├── store/
│   ├── store.go          // Load, Append, UpdateStatus
│   └── store_test.go
├── verify/
│   ├── verify.go         // Verify, VerifyAll, Result
│   ├── sign.go           // Sign, HMAC-SHA256
│   └── verify_test.go
├── audit/
│   ├── audit.go          // ChainedAuditLog, AuditCountCreated
│   ├── chain.go          // ChainFile, AppendEntry
│   └── audit_test.go
├── forward/
│   ├── syslog.go         // ForwardSyslog
│   ├── webhook.go        // ForwardWebhook
│   └── forward_test.go
└── rules/
    ├── rules.go          // ValidateBusinessRules
    └── rules_test.go
```

**Critérios:**
- `pkg/accept` torna-se um package de re-exportação (opcional) para backward compatibility, marcado como deprecated na v2.5 e removido na v3.0.
- `ConfigHash` move-se para `internal/cpl` (o seu domínio é canonicalização, não aceitação de risco).
- `ReadReport` move-se para `pkg/report/reader.go`.

#### 4.2.6. Sorting Idiomático

**Local:** `main.go` (roadmap sorting).

**Antigo:**
```go
for i := 0; i < len(sortedRoadmap); i++ {
    for j := i + 1; j < len(sortedRoadmap); j++ {
        if sortedRoadmap[i].FinalScore < sortedRoadmap[j].FinalScore {
            sortedRoadmap[i], sortedRoadmap[j] = sortedRoadmap[j], sortedRoadmap[i]
        }
    }
}
```

**Novo:**
```go
slices.SortFunc(sortedRoadmap, func(a, b model.Finding) int {
    return cmp.Compare(b.FinalScore, a.FinalScore) // descending
})
```

#### 4.2.7. Fuzzing com Invariantes

**Local:** `pkg/ingestion/ingestion_fuzz_test.go`.

**Antigo:**
```go
f.Fuzz(func(t *testing.T, data []byte) {
    _ = os.WriteFile("fuzz.yaml", data, 0600)
    _, _ = loadYAML("fuzz.yaml")
})
```

**Novo:**
```go
f.Fuzz(func(t *testing.T, data []byte) {
    _ = os.WriteFile("fuzz.yaml", data, 0600)
    controls, err := loadYAML("fuzz.yaml")
    if err != nil {
        return // invalid input is OK
    }
    // Invariant: se o parse teve sucesso, todos os controls devem ter ID e Name não vazios
    for _, c := range controls {
        if c.ID == "" {
            t.Fatalf("parsed control with empty ID")
        }
        if c.Name == "" {
            t.Fatalf("parsed control with empty Name")
        }
        if c.Maturity < 0 || c.Maturity > 5 {
            t.Fatalf("parsed control with invalid maturity: %d", c.Maturity)
        }
    }
})
```

Adicionar fuzz tests para `pkg/cli/pathguard.go` (inputs maliciosos de path) e `pkg/accept/verify` (payloads de assinatura corrompidos).

---

## 5. Critérios de Aceitação

### 5.1. Eixo A

- [ ] `go.mod` declara `go 1.27.0`.
- [ ] CI passa em Go 1.27.0 sem regressões.
- [ ] `go fix ./...` não produz alterações (gate no CI).
- [ ] `go test ./...` passa com `stdversion` vet ativo.
- [ ] Docker image builda com `golang:1.27-alpine`.
- [ ] Benchmarks de `pkg/ingestion` e `pkg/epss` mostram melhoria ≥ 0.5% (ou sem regressão > 1%).

### 5.2. Eixo B

- [ ] `main.go` tem ≤ 80 linhas de lógica de negócio (orquestração delegada a `pkg/orchestrator`).
- [ ] `cmd/evaluate/evaluate.go` tem ≤ 100 linhas (idem).
- [ ] Zero ocorrências de `os.ReadFile` + `#nosec G304` fora de `pkg/cli/safefile.go`.
- [ ] Zero ocorrências de `fmt.Fprintf(os.Stderr, ...)` em `pkg/*` (logging via `slog`).
- [ ] Todos os métodos de `Anchorer` propagam `context.Context` até à chamada de rede final.
- [ ] `pkg/accept` decomposto em sub-packages; nenhum import circular.
- [ ] Sorting manual substituído por `slices.SortFunc`.
- [ ] Fuzz tests verificam invariantes de propriedade (não apenas ausência de panic).
- [ ] Cobertura de testes de `pkg/orchestrator` ≥ 80%.

---

## 6. Plano de Implementação

### Fase 1 — Fundação (1 semana)
1. Criar branch `feat/v2.5.0-go127`.
2. Atualizar `go.mod`, CI, Dockerfile.
3. Correr `go fix ./...` e `go mod tidy`.
4. Resolver quebras de `encoding/json` v2 (mensagens de erro).
5. Merge da Fase 1 para `main` (ou manter em branch longa).

### Fase 2 — I/O & Logging (1 semana)
1. Criar `pkg/cli/safefile.go`.
2. Substituir todas as leituras/escritas dispersas.
3. Introduzir `pkg/ui/logger.go` com `slog`.
4. Migrar `pkg/epss`, `pkg/statestore`, `pkg/accept` para `slog`.

### Fase 3 — Context & Network (3 dias)
1. Propagar `context.Context` em `pkg/epss`, `pkg/provenance`, `internal/notification`.
2. Actualizar testes para passar `context.Background()`.

### Fase 4 — Refactor Estrutural (2 semanas)
1. Criar `pkg/orchestrator` com `EvaluationPipeline`.
2. Extrair lógica de `main.go` e `cmd/evaluate`.
3. Decompor `pkg/accept` em sub-packages.
4. Mover `ConfigHash` para `internal/cpl`.
5. Mover `ReadReport` para `pkg/report`.
6. Substituir sorting manual.

### Fase 5 — Testes & Hardening (1 semana)
1. Fortalecer fuzz tests com invariantes.
2. Adicionar fuzz tests para `pathguard` e `verify`.
3. Escrever testes unitários para `pkg/orchestrator`.
4. Correr suite completa: `go test -race ./...`.
5. Correr `golangci-lint run`.
6. Revisão de segurança (crypto audit tests passam).

### Fase 6 — Release (2 dias)
1. Atualizar `CHANGELOG.md`.
2. Atualizar `README.md` (requisito Go ≥ 1.27).
3. Tag `v2.5.0`.
4. Gerar chain-seal e assinar release.

---

## 7. Riscos e Mitigações

| Risco | Probabilidade | Impacto | Mitigação |
|-------|--------------|---------|-----------|
| `encoding/json` v2 quebra testes com string matching | Média | Médio | Auditar todos os testes JSON antes do merge; usar `errors.As` ou prefixos. |
| Refactor de `pkg/accept` introduz import cycles | Baixa | Alto | Desenhar DAG de packages antes de mover ficheiros; usar `internal/` se necessário. |
| `slog` muda output format em testes que verificam stderr | Média | Baixo | Os testes de stderr devem ser substituídos por testes de `slog.Handler` customizado ou por verificação de eventos estruturados. |
| `EvaluationPipeline` aumenta complexidade inicial | Baixa | Médio | Manter `runWardex` e `runEvaluate` como thin wrappers durante uma release de transição; depreciar gradualmente. |
| Go 1.27 ainda em RC | Baixa | Alto | Aguardar release final (RC3 já lançado, release final previsto para agosto 2026). Não mergear antes do GA. |

---

## 8. Referências

1. Go 1.27 Release Notes — https://go.dev/doc/go1.27
2. `encoding/json` v2 — https://pkg.go.dev/encoding/json/v2
3. `log/slog` — https://pkg.go.dev/log/slog
4. Wardex `SPEC_wardex_v2.0_CRA_Art14.md`
5. Wardex `SPEC_wardex_v2.0.1_sdlc_hardening.md`
6. Wardex `doc/architecture/ENGINEERING_BLUEPRINT.md`
7. CWE-22 (Path Traversal) — https://cwe.mitre.org/data/definitions/22.html
8. Go Fuzzing — https://go.dev/doc/security/fuzz

---

*End of Specification*
