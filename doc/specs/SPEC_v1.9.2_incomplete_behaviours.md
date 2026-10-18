# SPEC — Wardex v1.9.2 Incomplete Behaviours

**Versão:** 1.0.0-draft
**Autor:** André Ataíde
**Data:** 2026-05-10
**Estado:** DRAFT — pendente review
**Bump:** PATCH (v1.9.1 → v1.9.2)

---

## Problema

Três comportamentos que a arquitectura do Wardex anuncia como parte do seu contrato
não estão implementados em `wardex evaluate`. Não são features em falta — são o
comportamento esperado por defeito dado o que já existe no código.

A referência é o próprio README e o fluxo descrito na documentação:
o `evaluate` deve consumir evidência canonicalizada, tomar uma decisão com base numa
configuração assinada, e registar essa decisão num log persistente. Dois dos três passos
estão parcialmente implementados (a decisão é tomada; a config pode ser assinada);
o terceiro (o registo da decisão) está ausente.

### G1 — Decision log ausente

`wardex evaluate` escreve a decisão de gate (allow / warn / block) para **stdout**
como tabela markdown. Não existe registo persistente de cada decisão de gate.

O `wardex-accept-audit.log` regista acceptances (excepções aprovadas). A infra-estrutura
está implementada: `pkg/accept/audit.go` tem `AuditLog()` com mutex, JSONL append-only,
safe path; `pkg/model/audit.go` tem `AuditEntry` com `ConfigHash`, `Risk`, `Status`,
`Detail`. O modelo de dados e o mecanismo de escrita existem. O que não existe é a
chamada a `AuditLog()` no caminho de avaliação do gate.

**Consequência:** um auditor pode ver acceptances com rasto completo (quem aceitou,
quando, com que configuração). Não pode ver o histórico de decisões de gate. A decisão
"allow" de um build de três meses atrás é irrecuperável sem reconstituição a partir de
CI logs, que em ambientes efémeros podem já não existir.

### G2 — Evidência não validada como envelope canónico

`wardex evaluate` aceita o ficheiro `--evidence` sem verificar que passou pelo
`wardex convert`. O código em `cmd/evaluate/evaluate.go:213` desserializa directamente
qualquer YAML com a chave `vulnerabilities:` — incluindo output bruto de Trivy ou
Grype que coincida parcialmente com o schema.

O envelope canónico interno tem campos obrigatórios que o output de scanner não
garante: `reachable` (por defeito `true` se ausente — comportamento conservador mas
silencioso), `epss_score` (por defeito `0.0`, o que o scorer trata como EPSS=1.0 no
caminho pessimista). Um ficheiro de evidência não-convertido que passe silenciosamente
pode produzir decisões incorrectas sem aviso.

**Consequência:** o pipeline pode chamar `wardex evaluate` directamente sobre output de
Trivy. Isto viola o invariante de canonicalização, mas o `evaluate` não o detecta nem
o rejeita.

### G3 — Forwarding do decision log não conectado ao evaluate

`pkg/accept/forward.go` tem `Forwarder` interface, `ForwardMultiplexer`, e
`SyslogBackend` implementado. `WebhookNotifier` está implementado para eventos de
acceptance. Nenhum destes mecanismos é chamado pelo `evaluate` — existem apenas no
caminho das acceptances.

O decision log sem forwarding só persiste enquanto o agente de build existir. Em
pipelines efémeros (GitHub Actions, runners containerizados), o `wardex-gate-audit.log`
desaparece com o runner. Syslog está implementado e pronto; conectá-lo ao decision log
fecha o gap de persistência sem novo código.

---

## Scope

### In scope

- **G1**: chamar `AuditLog()` no final de `runEvaluate`, escrevendo uma entrada por
  cada decisão de gate (uma linha no JSONL por avaliação, não por vulnerabilidade).
  Ficheiro: `wardex-gate-audit.log` por defeito, configurável via flag
  `--gate-log <path>`.

- **G1**: estender `model.AuditEntry` com dois campos adicionais necessários para o
  decision log: `EvidenceHash string` (SHA-256 do ficheiro de evidência) e
  `OverallDecision string` (allow / warn / block). Os campos existentes (`ConfigHash`,
  `Risk`, `Status`, `Detail`) cobrem o resto.

- **G2**: validar no `evaluate` que o envelope de evidência contém pelo menos um campo
  que identifique proveniência da conversão, **ou** emitir warning explícito quando
  nenhum campo de proveniência está presente. A validação não deve bloquear por
  defeito (backward compatibility com pipelines existentes); com `--strict` deve
  bloquear.

- **G2**: definir o campo de proveniência no envelope canónico. Proposta:
  `converted_by: string` (e.g. `"wardex-convert/grype"`, `"wardex-convert/cyclonedx"`).
  Adicionado pelo `wardex convert`; ausente em envelopes construídos manualmente ou
  ingeridos de scanner directo.

- **G3**: chamar `ForwardMultiplexer.Dispatch()` no caminho do decision log quando
  backends estiverem configurados. O SyslogBackend está implementado; a ligação ao
  `evaluate` não está. Configuração via config YAML existente (novo bloco `gate_log`
  dentro de `reporting`).

### Out of scope

- Novos backends de forwarding além de Syslog (S3, GCS, Rekor) — diferido. A interface
  `Forwarder` é extensível; novos backends entram sem alterar o contrato.
- Chaining criptográfico de entradas do decision log (hash da entrada anterior em cada
  nova entrada) — diferido. O JSONL append-only com forwarding imediato para Syslog é
  suficiente para os requisitos de auditabilidade declarados; o chaining é melhoria de
  integridade para versão futura.
- Granularidade por vulnerabilidade no decision log — a entrada regista a decisão
  global do gate (allow / warn / block), não uma linha por CVE. O breakdown por CVE
  já está em stdout; duplicá-lo no log aumenta volume sem benefício de auditoria.

---

## Data Model

### Extensão de `model.AuditEntry`

```go
// Campos adicionados em v1.9.2 para suporte ao decision log de gate.
// Campos existentes (Timestamp, Event, ConfigHash, Risk, Status, Detail) permanecem.
type AuditEntry struct {
    // ... campos existentes ...
    EvidenceHash    string `json:"evidence_hash,omitempty"`    // SHA-256 do ficheiro --evidence
    OverallDecision string `json:"overall_decision,omitempty"` // "allow" | "warn" | "block"
}
```

### Campo de proveniência no envelope canónico

```yaml
# Adicionado pelo wardex convert; ausente em envelopes manuais.
converted_by: "wardex-convert/grype"   # ou "wardex-convert/cyclonedx", etc.

vulnerabilities:
  - cve_id: "CVE-2024-1234"
    cvss_base: 9.1
    # ...
```

Struct correspondente em `model.VulnerabilityEnvelope` (novo tipo que envolve o slice
actual):

```go
type VulnerabilityEnvelope struct {
    ConvertedBy     string          `yaml:"converted_by,omitempty"`
    Vulnerabilities []Vulnerability `yaml:"vulnerabilities"`
}
```

### Novo bloco `gate_log` em `ReportingConfig`

```go
type GateLogConfig struct {
    Path     string   `yaml:"path"`     // default: "wardex-gate-audit.log"
    Forward  []string `yaml:"forward"`  // e.g. ["syslog"]
    OnFail   string   `yaml:"on_fail"`  // "warn" | "block"; default: "warn"
}

type ReportingConfig struct {
    Format  string        `yaml:"format"`
    Output  string        `yaml:"output"`
    GateLog GateLogConfig `yaml:"gate_log"`
}
```

---

## Comportamento esperado após v1.9.2

### Decision log (G1)

```
$ wardex evaluate --config wardex.wexstate --evidence wardex-vulns.yaml

[INFO] Sealed config verified — signed by andre@example.com (c-admin-01) at 2026-05-10 14:32 UTC
[INFO] Gate decision logged → wardex-gate-audit.log

## Release Gate — Evaluation
| CVE | CVSS | EPSS | Release Risk | Decision |
...
**Overall Decision:** warn  |  Gate Maturity: Level 2
```

Entrada JSONL correspondente em `wardex-gate-audit.log`:

```json
{
  "ts": "2026-05-10T14:32:11Z",
  "event": "gate.evaluated",
  "config_hash": "sha256:abc123...",
  "evidence_hash": "sha256:def456...",
  "overall_decision": "warn",
  "risk": 0.14,
  "status": "warn",
  "detail": "2 vulnerabilities above warn_above threshold"
}
```

### Validação de proveniência (G2)

```
# Com ficheiro sem converted_by (e.g. output Trivy directo):
$ wardex evaluate --evidence trivy-output.yaml
[WARN] Evidence file has no 'converted_by' field. Run 'wardex convert' to canonicalise
       scanner output. Proceeding with available fields; missing fields default to
       conservative values (reachable=true, epss=1.0).

# Com --strict:
$ wardex evaluate --strict --evidence trivy-output.yaml
[ERROR] --strict requires canonicalised evidence. Run 'wardex convert grype|cyclonedx|...'
        before evaluate.
exit code 3
```

### Forwarding para Syslog (G3)

```yaml
# wardex-config.yaml
reporting:
  format: markdown
  output: wardex-report.md
  gate_log:
    path: wardex-gate-audit.log
    forward: ["syslog"]
    on_fail: warn
```

---

## Testing

### Novos testes

**`cmd/evaluate/evaluate_gate_log_test.go`**
- `TestEvaluateWritesGateAuditLog`: corre `runEvaluate` com fixture de evidência
  e verifica que `wardex-gate-audit.log` foi criado com uma entrada JSONL contendo
  `event: "gate.evaluated"`, `config_hash` não-vazio, `evidence_hash` não-vazio,
  e `overall_decision` com valor válido.
- `TestEvaluateGateLogAppendsNotOverwrites`: corre `runEvaluate` duas vezes sobre
  o mesmo log path; verifica que o ficheiro tem duas linhas.

**`cmd/evaluate/evaluate_provenance_test.go`**
- `TestEvaluateWarnsOnMissingConvertedBy`: evidência sem `converted_by` → stderr
  contém o warning; exit code não é 3.
- `TestEvaluateStrictRejectsNonCanonical`: `--strict` + evidência sem `converted_by`
  → exit code 3.
- `TestEvaluateAcceptsCanonicalEnvelope`: evidência com `converted_by` →
  nenhum warning, avaliação normal.

**`config/config_examples_test.go`** (extensão)
- Adicionar `doc/examples/wardex-config.yaml` ao teste `TestPublishedExamplesMatchSchema`
  após adicionar o bloco `gate_log` ao exemplo. O teste já existe; basta garantir que
  o novo bloco é coberto pelo KnownFields(true).

### Existing tests

`go test ./...` deve passar sem alterações após a extensão de `AuditEntry` (campos
novos são `omitempty`; fixtures existentes não os incluem e continuam válidas).

---

## Files Changed

| Ficheiro | Operação | Notas |
|---|---|---|
| `pkg/model/audit.go` | MODIFIED | Adicionar `EvidenceHash` e `OverallDecision` a `AuditEntry`. |
| `pkg/model/release.go` | MODIFIED | Adicionar `VulnerabilityEnvelope` com `ConvertedBy` e `Vulnerabilities`. |
| `config/config.go` | MODIFIED | Adicionar `GateLogConfig` e campo `GateLog` em `ReportingConfig`. |
| `cmd/convert/grype.go` | MODIFIED | Popular `converted_by: "wardex-convert/grype"` no output. |
| `cmd/convert/sbom.go` | MODIFIED | Popular `converted_by: "wardex-convert/cyclonedx"` (ou variante) no output. |
| `cmd/evaluate/evaluate.go` | MODIFIED | (1) Deserializar para `VulnerabilityEnvelope` em vez de struct inline. (2) Validar `ConvertedBy`. (3) Calcular `EvidenceHash`. (4) Chamar `AuditLog()` com entrada de gate no final. (5) Chamar `ForwardMultiplexer.Dispatch()` se `GateLog.Forward` configurado. |
| `doc/examples/wardex-config.yaml` | MODIFIED | Adicionar bloco `gate_log` com valores de exemplo. |
| `cmd/evaluate/evaluate_gate_log_test.go` | NEW | Testes de escrita do decision log. |
| `cmd/evaluate/evaluate_provenance_test.go` | NEW | Testes de validação de proveniência. |
| `main.go` | MODIFIED | `Version = "1.9.1"` → `Version = "1.9.2"` |
| `CHANGELOG.md` | MODIFIED | Nova entrada `## [1.9.2]`. |
| `doc/releases/v1.9.2-notes.md` | NEW | Release notes. |

---

## Compatibilidade

**Envelopes de evidência existentes** — o campo `converted_by` é `omitempty`; envelopes
sem ele carregam sem erro e produzem warning (ou exit 3 com `--strict`). Comportamento
de avaliação idêntico ao v1.9.1.

**`wardex-gate-audit.log`** — ficheiro novo criado por defeito no directório de trabalho.
Pipelines que não queiram o ficheiro podem redirigir com `--gate-log /dev/null`.

**`AuditEntry` com campos novos** — `omitempty`; entradas existentes em
`wardex-accept-audit.log` lidas por `AuditCountCreated()` não são afectadas.

**`ReportingConfig` com `GateLog`** — o bloco `gate_log:` é opcional no YAML;
`GateLogConfig` com zero values usa o path por defeito e sem forwarding. O teste
`TestPublishedExamplesMatchSchema` detectará divergência se o exemplo não for
actualizado.

---

## Open Questions

**Q1 — `--gate-log` como flag ou exclusivamente via config?**

Flag dá flexibilidade em CI (override sem editar config); config dá governação (o path
faz parte da configuração selada). Proposta: ambos, com a flag a tomar precedência
sobre o config, tal como `--fail-above` toma precedência sobre `release_gate.warn_above`.

**Q2 — Chaining criptográfico das entradas do decision log?**

Cada entrada incluir o hash da anterior tornaria o log tamper-evident ao nível da
sequência (não apenas das entradas individuais). Custo: leitura da última linha antes
de cada escrita; complexity de verificação. Diferido para v1.10.x; a prioridade agora
é ter o log, não o maximizar.

**Q3 — `converted_by` como campo livre ou enum controlado?**

String livre permite extensibilidade (conversores de terceiros). Enum controlado
permite validação estrita. Proposta: string livre com prefixo `wardex-convert/` para
conversores oficiais; qualquer outro valor passa o warning mas não bloqueia.
