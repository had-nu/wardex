# SPEC — Wardex v1.9.1 Schema Cleanup

**Versão:** 1.0.0-draft
**Autor:** André Ataíde
**Data:** 2026-05-08
**Estado:** DRAFT — pendente review
**Bump:** PATCH (v1.9.0 → v1.9.1)

---

## Problema

A `config.Config` declara campos que não têm consumidor em qualquer caminho de
código activo. Utilizadores escrevem `wardex-config.yaml` com esses campos, calibram-nos
com cuidado e não observam efeito comportamental. Isto quebra o contrato implícito entre
o YAML e o que o `wardex evaluate` faz — e é um footgun para qualquer adoção, independente
do sector, dimensão ou maturidade da organização que adopta o Wardex.

A varredura ao código (grep sobre `pkg/`, `cmd/`, `internal/`, `config/`, excluindo
`_test.go` e o ficheiro de definição) identifica cinco blocos sem consumidor activo:

| Bloco | Definição em `config/config.go` | Consumidor activo |
|---|---|---|
| `organization` (`name`, `sector`, `scope`) | `Config.Organization` | nenhum |
| `domain_weights` | `Config.DomainWeights` | nenhum |
| `control_weights` | `Config.ControlWeights` | nenhum |
| `thresholds` (`fail_above`, `warn_above`) | `Config.Thresholds` | nenhum |
| `reporting.verbose` | `ReportingConfig.Verbose` | nenhum (a flag CLI `--verbose` em `main.go:50` é independente do YAML) |

Há ainda três problemas correlatos em ficheiros que envolvem o schema:

**P1 — Exemplo publicado ensina formato inválido.** O `doc/examples/wardex-config.yaml`,
que vai com cada release, contém:

```yaml
thresholds:
  critical_vulnerabilities: 0
  high_vulnerabilities: 2
```

As chaves `critical_vulnerabilities` e `high_vulnerabilities` não existem nem em
`Config.Thresholds` (que tem `fail_above`/`warn_above`) nem em qualquer outra struct do
schema. Utilizadores que copiem este exemplo escrevem configuração que não é validada
nem aplicada — falha silenciosa.

**P2 — Duplicação semântica que confunde.** `release_gate.warn_above` (consumido pelo
scorer) e `thresholds.warn_above` (orfão) coexistem como duas formas de soletrar a
mesma intenção. Um utilizador que defina apenas `thresholds.warn_above` obtém o valor
default (0) no gate e nenhum aviso de erro.

**P3 — Test fixture com schema inválido.** O `test/testdata/wardex-config.yaml`
contém blocos `organization:`, `domain_weights:` e `accept:` (linha 34, com
`hmac_secret_env: WARDEX_ACCEPT_SECRET`). O bloco `accept:` usa a chave errada
— a chave válida é `acceptance:` (tag YAML em `Config.AcceptanceConfig`) — e o subcampo
`hmac_secret_env` não existe em `AcceptanceConfig`. O HMAC secret é lido directamente da
env var `WARDEX_ACCEPT_SECRET` em `pkg/accept/signer.go:73`, não do YAML. O ficheiro
testdata é exemplo enganador para qualquer pessoa que abra o repositório a estudar o
schema.

---

## Scope

### In scope

- Remoção dos cinco campos orfãos de `config/config.go`
- Reescrita de `doc/examples/wardex-config.yaml` para reflectir o schema vivo
- Limpeza de `test/testdata/wardex-config.yaml` (remoção de blocos `organization:`,
  `domain_weights:` e `accept:`)
- Anotação histórica em `internal/SPEC_wardex_trust_.md` (linha ~345 referencia
  `domain_weights.technological: "PENDING_APPROVAL"` num exemplo de seal — esse exemplo
  fica obsoleto)
- Bump da constante `Version` em `main.go:41` para `"1.9.1"`
- Entrada de CHANGELOG explícita listando os campos removidos
- Release notes em `doc/releases/v1.9.1-notes.md`
- Teste de regressão garantindo que YAMLs com os campos removidos continuam a carregar
  sem erro (compatibilidade backward)

### Out of scope

- Novas features de scoring derivadas de maturidade SAMM/BSIMM/SSDF — diferido para v1.10.x
- Reintrodução de `organization` como metadata informativa — diferido
- Flag `--strict` que rejeite campos desconhecidos no YAML — diferido
- Wiring de `domain_weights` ou `control_weights` como capacidade real — diferido para
  v1.10.x condicional a desenho explícito de como interagem com `compensating_controls`
  e `asset_context`

A regra que define o que fica fora: Wardex deve resolver problemas semelhantes em
contextos organizacionais distintos. Adicionar features ou re-introduzir campos antes
de existir caso de uso concreto e reproduzível repete o erro que esta SPEC corrige.

---

## Data Model

Pike Regra 5: as structs que sobrevivem ao cleanup correspondem 1:1 a comportamento
observável. Não há campos cosméticos.

### Antes (v1.9.0)

```go
type Organization struct {
    Name   string `yaml:"name"`
    Sector string `yaml:"sector"`
    Scope  string `yaml:"scope"`
}

type ControlWeight struct {
    Weight        float64 `yaml:"weight"`
    Justification string  `yaml:"justification"`
}

type Thresholds struct {
    FailAbove float64 `yaml:"fail_above"`
    WarnAbove float64 `yaml:"warn_above"`
}

type ReportingConfig struct {
    Format  string `yaml:"format"`
    Output  string `yaml:"output"`
    Verbose bool   `yaml:"verbose"`
}

type Config struct {
    Organization     Organization             `yaml:"organization"`
    DomainWeights    map[string]float64       `yaml:"domain_weights"`
    ControlWeights   map[string]ControlWeight `yaml:"control_weights"`
    ReleaseGate      ReleaseGate              `yaml:"release_gate"`
    Thresholds       Thresholds               `yaml:"thresholds"`
    AcceptanceConfig AcceptanceConfig         `yaml:"acceptance"`
    Reporting        ReportingConfig          `yaml:"reporting"`
    Profiles         map[string]Profile       `yaml:"profiles"`
}
```

### Depois (v1.9.1)

```go
// Organization, ControlWeight e Thresholds removidos.

type ReportingConfig struct {
    Format string `yaml:"format"`
    Output string `yaml:"output"`
    // Verbose removido — a flag CLI --verbose em main.go é a fonte de verdade.
}

type Config struct {
    ReleaseGate      ReleaseGate        `yaml:"release_gate"`
    AcceptanceConfig AcceptanceConfig   `yaml:"acceptance"`
    Reporting        ReportingConfig    `yaml:"reporting"`
    Profiles         map[string]Profile `yaml:"profiles"`
}
```

`ReleaseGate`, `AcceptanceConfig` (com `Limits` e `BannedJustificationPhrases`) e
`Profile` permanecem inalterados — todos têm consumidores activos verificados.

---

## Compatibilidade

**YAMLs existentes carregam sem erro.**

`gopkg.in/yaml.v3` ignora silenciosamente campos desconhecidos por defeito (sem
`KnownFields(true)`). Configs com blocos `organization:`, `domain_weights:`,
`control_weights:`, `thresholds:` ou `reporting.verbose:` continuam a carregar e o
gate continua a decidir com base em `release_gate` e `acceptance`. O comportamento
não muda — esses blocos eram já silenciosamente ignorados em runtime; v1.9.1 apenas
torna essa realidade explícita ao remover do schema documentado.

Não há script de migração necessário. Recomenda-se que utilizadores actualizem os
seus YAMLs para reflectir o schema vivo (o exemplo limpo em
`doc/examples/wardex-config.yaml`), mas sem urgência operacional.

---

## Testing

### Regressão de compatibilidade

Adicionar `config/config_v191_test.go`:

```go
package config

import (
    "os"
    "path/filepath"
    "testing"
)

// TestLoadConfigWithRemovedFields garante que YAMLs escritos para v1.9.0,
// contendo campos removidos em v1.9.1, continuam a carregar sem erro.
// Os campos removidos eram já silenciosamente ignorados em runtime; este
// teste codifica essa garantia para evitar regressão futura.
func TestLoadConfigWithRemovedFields(t *testing.T) {
    legacyYAML := `
organization:
  name: "Legacy Org"
  sector: "automotive"
  scope: "ISMS perimeter"

domain_weights:
  technological: 1.5
  organizational: 1.0

control_weights:
  CTRL-001:
    weight: 1.2
    justification: "legacy"

thresholds:
  fail_above: 0.5
  warn_above: 0.3

release_gate:
  enabled: true
  risk_appetite: 0.20
  warn_above: 0.12

reporting:
  format: "markdown"
  verbose: true
`
    dir := t.TempDir()
    path := filepath.Join(dir, "legacy-config.yaml")
    if err := os.WriteFile(path, []byte(legacyYAML), 0o600); err != nil {
        t.Fatalf("write legacy fixture: %v", err)
    }

    cfg, err := Load(path)
    if err != nil {
        t.Fatalf("legacy config should load without error, got: %v", err)
    }
    if !cfg.ReleaseGate.Enabled {
        t.Error("ReleaseGate.Enabled should be true after load")
    }
    if cfg.ReleaseGate.RiskAppetite != 0.20 {
        t.Errorf("expected RiskAppetite 0.20, got %v", cfg.ReleaseGate.RiskAppetite)
    }
    if cfg.ReleaseGate.WarnAbove != 0.12 {
        t.Errorf("expected WarnAbove 0.12, got %v", cfg.ReleaseGate.WarnAbove)
    }
    if cfg.Reporting.Format != "markdown" {
        t.Errorf("expected Reporting.Format 'markdown', got %q", cfg.Reporting.Format)
    }
}
```

### Output equivalence (smoke)

Comparar output de `wardex evaluate --config <fixture>` em v1.9.0 e v1.9.1 sobre o
mesmo conjunto de evidências. Decisões devem ser bit-for-bit idênticas no que toca
a ALLOW/WARN/BLOCK. Não é suite formal — é validação manual antes da tag.

### Existing tests

`go test ./...` passa sem alterações ao corpus actual. `config/config_profile_test.go`
opera sobre YAML inline (não depende de `test/testdata/wardex-config.yaml`), e os
campos `Profiles` e `ReleaseGate` permanecem inalterados.

---

## Files Changed

| Ficheiro | Operação | Notas |
|---|---|---|
| `config/config.go` | MODIFIED | Remover structs `Organization`, `ControlWeight`, `Thresholds` e respectivos campos em `Config`. Remover `ReportingConfig.Verbose`. |
| `doc/examples/wardex-config.yaml` | REWRITTEN | Substituir bloco `thresholds:` (que usa chaves inexistentes) pelo schema vivo. Manter exemplos de `release_gate`, `acceptance`, `reporting`, `profiles`. |
| `test/testdata/wardex-config.yaml` | MODIFIED | Remover blocos `organization:`, `domain_weights:` e `accept:` (chave errada). |
| `internal/SPEC_wardex_trust_.md` | ANNOTATED | Adicionar nota próximo da linha 345: o exemplo `domain_weights.technological: "PENDING_APPROVAL"` é histórico — o campo foi removido em v1.9.1; usar `release_gate.risk_appetite` ou outro campo vivo em exemplos futuros. |
| `main.go` (linha 41) | MODIFIED | `Version = "1.9.0"` → `Version = "1.9.1"` |
| `config/config_v191_test.go` | NEW | Regressão `TestLoadConfigWithRemovedFields` (ver acima). |
| `CHANGELOG.md` | MODIFIED | Nova entrada `## [1.9.1] — 2026-05-08` com secção `### Removed` listando os cinco campos. |
| `doc/releases/v1.9.1-notes.md` | NEW | Release notes para `gh release create`. |

### Anotação proposta para `internal/SPEC_wardex_trust_.md`

Adicionar imediatamente acima do bloco que contém a linha 345:

```markdown
> **Nota histórica (v1.9.1):** o exemplo abaixo referencia
> `domain_weights.technological` como campo passível de ser marcado
> `PENDING_APPROVAL`. Este campo foi removido do schema em v1.9.1
> (ver `SPEC_v1.9.1_schema_cleanup.md`) por nunca ter sido consumido
> pelo scorer. Para um exemplo equivalente em código vivo, usar
> `release_gate.risk_appetite` ou `acceptance.limits.max_acceptance_days`.
```

### Entrada proposta para `CHANGELOG.md`

```markdown
## [1.9.1] — 2026-05-08

### Removed

- `organization` block (`name`, `sector`, `scope`) — never consumed by the scorer or
  by `wardex assess`.
- `domain_weights` map — placeholder for an unshipped feature; removed pending a
  concrete use case.
- `control_weights` map — placeholder; same rationale.
- `thresholds` block (`fail_above`, `warn_above`) — duplicated `release_gate.warn_above`
  semantically and was never read. The live threshold field is `release_gate.warn_above`;
  the live CLI failure flag is `--fail-above` in `wardex evaluate`.
- `reporting.verbose` — the CLI flag `--verbose` is the source of truth.

### Fixed

- `doc/examples/wardex-config.yaml` rewritten to mirror the live schema (the previous
  `thresholds:` block used keys that did not match any field in the codebase).
- `test/testdata/wardex-config.yaml`: removed `organization:`, `domain_weights:`,
  and `accept:` blocks (the last used the wrong key — the schema field is `acceptance:`,
  and the HMAC secret is read from the `WARDEX_ACCEPT_SECRET` env var, not from YAML).

### Compatibility

YAML files written for v1.9.0 with the now-removed blocks continue to load without
error. The Go YAML decoder ignores unknown fields by default. No migration script
required.
```

---

## Open Questions

**Q1 — `organization` em v1.10.x?**

Pró: ficheiro auto-descritivo é útil em ambientes multi-tenant ou multi-cliente.
Contra: comentário YAML serve, e adicionar metadata sem efeito repete o problema que
esta SPEC corrige. Recomendação tentativa: voltar apenas se ficar acoplado a
`audit_metadata` no output do `evaluate`/`assess`, com efeito real (e.g., aparece no
header de relatórios e nos envelopes assinados). Decisão a tomar antes do próximo
minor bump.

**Q2 — `--strict` para rejeitar campos desconhecidos?**

Útil em CI: detectaria erros de tipo do utilizador (`risk_apetite` em vez de
`risk_appetite`). Custo: quebra a backward compatibility de YAMLs antigos. Recomendação
tentativa: introduzir como flag opt-in, off por defeito, em v1.10.x. Implementação:
chamar `decoder.KnownFields(true)` quando a flag estiver activa.

**Q3 — `domain_weights` re-introduzido com semântica real?**

A intenção original (calibração inversa a partir de assessment SAMM/BSIMM/SSDF) faz
sentido conceptualmente mas não faz sentido neste schema sem desenho explícito de como
`domain_weights` interage com `compensating_controls` e `asset_context`. Diferido até
existir caso de uso concreto reproduzível em mais de uma organização — consistente com
a regra de scope: Wardex resolve problemas semelhantes em contextos distintos.
