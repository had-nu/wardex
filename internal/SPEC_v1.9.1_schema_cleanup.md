# SPEC — Wardex v1.9.1 Schema Cleanup

**Versão:** 1.1.0-draft
**Autor:** André Ataíde
**Data:** 2026-05-09
**Estado:** DRAFT — pendente review
**Bump:** PATCH (v1.9.0 → v1.9.1)
**Histórico:** v1.0 (2026-05-08) cobria cinco campos em `config/config.go`; v1.1 alarga
o cleanup a `pkg/model/release.go` após auditoria revelar campo orfão da mesma classe,
e adiciona regression test de schema que cobre os ficheiros publicados como exemplo.

---

## Problema

O schema do Wardex declara campos que não têm consumidor em qualquer caminho de código
activo. Utilizadores escrevem YAML, calibram-nos com cuidado e não observam efeito
comportamental. Isto quebra o contrato implícito entre o YAML e o que o `wardex evaluate`
faz — e é um footgun para qualquer adoção, independente do sector, dimensão ou
maturidade da organização que adopta o Wardex.

A varredura sistemática (grep sobre `pkg/`, `cmd/`, `internal/`, `config/`, excluindo
`_test.go` e ficheiros de definição) identifica **seis** campos sem consumidor activo
em duas localizações distintas:

### Em `config/config.go`

| Bloco | Definição | Consumidor activo |
|---|---|---|
| `organization` (`name`, `sector`, `scope`) | `Config.Organization` | nenhum |
| `domain_weights` | `Config.DomainWeights` | nenhum |
| `control_weights` | `Config.ControlWeights` | nenhum |
| `thresholds` (`fail_above`, `warn_above`) | `Config.Thresholds` | nenhum |
| `reporting.verbose` | `ReportingConfig.Verbose` | nenhum (a flag CLI `--verbose` em `main.go:50` é independente do YAML) |

### Em `pkg/model/release.go`

| Campo | Definição | Consumidor activo |
|---|---|---|
| `data_class` | `model.AssetContext.DataClass` (linha 21) | nenhum (o scorer em `pkg/releasegate/scorer.go` lê `Criticality`, `InternetFacing`, `RequiresAuth`, `Environment` — não `DataClass`) |

Há ainda **quatro** problemas correlatos em ficheiros que envolvem o schema:

**P1 — Exemplo publicado ensina chaves inexistentes (`thresholds`).** O
`doc/examples/wardex-config.yaml` em v1.9.0 contém:

```yaml
thresholds:
  critical_vulnerabilities: 0
  high_vulnerabilities: 2
```

As chaves `critical_vulnerabilities` e `high_vulnerabilities` não existem nem em
`Config.Thresholds` (que tem `fail_above`/`warn_above`) nem em qualquer outra struct
do schema. Utilizadores que copiem este exemplo escrevem configuração que não é
validada nem aplicada — falha silenciosa.

**P2 — Exemplo publicado ensina chaves inexistentes (`compensating_controls`).** O
draft inicial de v1.9.1 corrigiu P1 mas introduziu uma reescrita igualmente
divergente do código:

```yaml
compensating_controls:
  - id: "WAF-01"
    name: "Cloudflare WAF"
    reduction: 0.15
```

Os campos correctos da struct `model.CompensatingControl` (linhas 26-30 de `release.go`)
são `type`, `effectiveness` e `justification`. Os três campos do exemplo (`id`, `name`,
`reduction`) não existem na struct e seriam silenciosamente ignorados, com o gate a
ler `Effectiveness=0.0` para todos os controlos declarados. Esta é exactamente a classe
de bug que a release devia corrigir, recriada em variante.

**P3 — Duplicação semântica em config (`warn_above`).** `release_gate.warn_above`
(consumido pelo scorer) e `thresholds.warn_above` (orfão) coexistiam como duas formas
de soletrar a mesma intenção. Um utilizador que definisse apenas `thresholds.warn_above`
obtinha o valor default (0) no gate e nenhum aviso.

**P4 — Test fixture com schema inválido.** O `test/testdata/wardex-config.yaml` em
v1.9.0 continha `organization:`, `domain_weights:` e `accept:` (chave errada — a chave
correcta é `acceptance:`). Após a primeira reescrita, o ficheiro continuou a usar os
mesmos campos inválidos em `compensating_controls` que o exemplo (P2), e ainda
`data_classification:` sob `release_gate.asset_context:` — chave que não existe em
`AssetContext` (que declara `data_class`).

### Causa raíz

Não existe validação automática de que YAMLs publicados correspondam ao schema vivo. O
`config_v191_test.go` testa que YAMLs **legacy** carregam sem erro (correcto, garantia
de backward compatibility), mas não testa que os ficheiros em `doc/examples/` e
`test/testdata/` se desserializam para todos os campos esperados sem campos
desconhecidos. Esta lacuna é a guard-rail em falta — adicionada em v1.9.1.

---

## Scope

### In scope

- Remoção dos cinco campos orfãos de `config/config.go` (`Organization`, `DomainWeights`,
  `ControlWeights`, `Thresholds`, `ReportingConfig.Verbose`)
- Remoção do campo orfão `DataClass` de `model.AssetContext` em `pkg/model/release.go`
- Reescrita de `doc/examples/wardex-config.yaml` para reflectir o schema vivo, com
  campos verificados contra structs
- Limpeza de `test/testdata/wardex-config.yaml`
- Anotação histórica em `internal/SPEC_wardex_trust_.md` (linha ~345 referencia
  `domain_weights.technological: "PENDING_APPROVAL"` num exemplo de seal — esse exemplo
  fica obsoleto)
- Bump da constante `Version` em `main.go:41` para `"1.9.1"`
- Entrada de CHANGELOG explícita listando os campos removidos
- Release notes em `doc/releases/v1.9.1-notes.md`
- **Regression test de schema** garantindo que (a) YAMLs com os campos removidos
  continuam a carregar sem erro (compatibilidade backward, já presente como
  `TestLoadConfigWithRemovedFields`); (b) os ficheiros publicados em `doc/examples/` e
  `test/testdata/` carregam com `KnownFields(true)` — falham se introduzirem campo
  desconhecido. Esta segunda parte é a guard-rail genérica que impede futura
  repetição em qualquer release.

### Out of scope

- Novas features de scoring derivadas de maturidade SAMM/BSIMM/SSDF — diferido para v1.10.x
- Reintrodução de `organization` como metadata informativa — diferido
- Reintrodução de `data_class` com semântica de scoring (multiplier por classificação
  de dados) — diferido para v1.10.x; o campo ressurge apenas com consumidor real
- Flag `--strict` que rejeite campos desconhecidos no YAML em runtime — diferido para
  v1.10.x como opt-in
- Wiring de `domain_weights` ou `control_weights` como capacidade real — diferido
- Consolidação entre `model.AssetContext` (release gate) e `model.AssetExposureContext`
  (asset envelopes), que partilham conceitos mas usam tags YAML diferentes
  (`data_class` vs `data_classification`) — diferido para v1.10.x

A regra que define o que fica fora: Wardex deve resolver problemas semelhantes em
contextos organizacionais distintos. Adicionar features ou re-introduzir campos antes
de existir caso de uso concreto e reproduzível repete o erro que esta SPEC corrige.

---

## Data Model

Pike Regra 5: as structs que sobrevivem ao cleanup correspondem 1:1 a comportamento
observável. Não há campos cosméticos — com uma única excepção documentada
(`CompensatingControl.Justification`).

### Antes (v1.9.0)

```go
// config/config.go
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

// pkg/model/release.go
type AssetContext struct {
    Criticality    float64 `yaml:"criticality"`
    InternetFacing bool    `yaml:"internet_facing"`
    RequiresAuth   bool    `yaml:"requires_auth"`
    DataClass      string  `yaml:"data_class"`    // não consumido pelo scorer
    Environment    string  `yaml:"environment"`
}
```

### Depois (v1.9.1)

```go
// config/config.go — Organization, ControlWeight e Thresholds removidos
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

// pkg/model/release.go — DataClass removido
type AssetContext struct {
    Criticality    float64 `yaml:"criticality"`
    InternetFacing bool    `yaml:"internet_facing"`
    RequiresAuth   bool    `yaml:"requires_auth"`
    Environment    string  `yaml:"environment"`
}
```

`ReleaseGate`, `AcceptanceConfig` (com `Limits` e `BannedJustificationPhrases`),
`Profile`, `CompensatingControl` permanecem inalterados — todos têm consumidores
activos verificados.

### Nota sobre `CompensatingControl.Justification`

```go
type CompensatingControl struct {
    Type          string  `yaml:"type"`
    Effectiveness float64 `yaml:"effectiveness"`
    Justification string  `yaml:"justification"` // não consumido pelo scorer
}
```

`Justification` não é lido por nenhum caminho de código — o scorer apenas soma
`Effectiveness`. **Mantido intencionalmente** porque serve auditabilidade humana:
um auditor que inspeccione `wardex-config.yaml` lê justificação textual de cada
controlo declarado. O paralelo é `AcceptanceConfig.BannedJustificationPhrases` (cuja
lógica também é mais sobre auditabilidade que sobre cálculo). A regra: **campos de
texto destinados a leitor humano em audit trail são preservados mesmo sem consumidor
de código**. A SPEC documenta isto explicitamente para que future cleanups não
removam por aplicação automática do princípio.

---

## Compatibilidade

**YAMLs existentes carregam sem erro.**

`gopkg.in/yaml.v3` ignora silenciosamente campos desconhecidos por defeito (sem
`KnownFields(true)`). Configs com blocos `organization:`, `domain_weights:`,
`control_weights:`, `thresholds:`, `reporting.verbose:` ou `release_gate.asset_context.data_class:`
continuam a carregar e o gate continua a decidir com base em `release_gate` e
`acceptance`. O comportamento não muda — esses blocos eram já silenciosamente ignorados
em runtime; v1.9.1 apenas torna essa realidade explícita ao remover do schema
documentado.

Não há script de migração necessário. Recomenda-se que utilizadores actualizem os
seus YAMLs para reflectir o schema vivo (o exemplo limpo em
`doc/examples/wardex-config.yaml`), mas sem urgência operacional.

---

## Testing

### Regressão de compatibilidade backward (já em v1.9.1)

`config/config_v191_test.go` contém `TestLoadConfigWithRemovedFields`, que carrega um
YAML inline com **todos** os campos removidos e valida que o load não falha e que os
campos vivos (`ReleaseGate.RiskAppetite`, `Reporting.Format`) são populados
correctamente. Esta garantia mantém-se.

A fixture em `config_v191_test.go` deve ser estendida para incluir
`release_gate.asset_context.data_class: "restricted"` (o sexto campo agora removido).

### Guard-rail nova: schema validation dos ficheiros publicados

Adicionar `config/config_examples_test.go`:

```go
package config

import (
    "bytes"
    "os"
    "path/filepath"
    "testing"

    "gopkg.in/yaml.v3"
)

// TestPublishedExamplesMatchSchema verifica que os ficheiros publicados como
// exemplo carregam contra o schema vivo sem campos desconhecidos. É a guard-rail
// que impede repetição da regressão de v1.9.1: schema documentado divergir do
// schema do código sem detecção em CI.
//
// `KnownFields(true)` força o decoder a falhar em qualquer chave que não
// corresponda a um yaml tag de Config, AssetContext, CompensatingControl ou
// outras structs nested.
func TestPublishedExamplesMatchSchema(t *testing.T) {
    targets := []struct {
        name string
        path string
    }{
        {"doc example", filepath.Join("..", "doc", "examples", "wardex-config.yaml")},
        {"testdata fixture", filepath.Join("..", "test", "testdata", "wardex-config.yaml")},
    }

    for _, tt := range targets {
        t.Run(tt.name, func(t *testing.T) {
            data, err := os.ReadFile(tt.path)
            if err != nil {
                t.Fatalf("read %s: %v", tt.path, err)
            }

            var cfg Config
            dec := yaml.NewDecoder(bytes.NewReader(data))
            dec.KnownFields(true)
            if err := dec.Decode(&cfg); err != nil {
                t.Fatalf("strict decode of %s: %v\n"+
                    "Hint: published example contains a field that does not "+
                    "match any yaml tag in Config or its nested structs. "+
                    "Update the example to match the live schema, or add the "+
                    "missing field to the struct.", tt.path, err)
            }
        })
    }
}
```

**Razão para guard-rail estar nos exemplos publicados, não em todo o load:** o
contrato externo (`Load()` chamado em runtime) deve continuar a aceitar campos
desconhecidos para preservar backward compatibility com YAMLs antigos. Mas os
ficheiros que **publicamos como referência** devem ser estritos — qualquer alteração
ao schema que invalide o exemplo bloqueia o CI antes do release.

### Output equivalence (smoke)

Comparar output de `wardex evaluate --config <fixture>` em v1.9.0 e v1.9.1 sobre o
mesmo conjunto de evidências. Decisões devem ser bit-for-bit idênticas no que toca a
ALLOW/WARN/BLOCK. Não é suite formal — é validação manual antes da retag.

### Existing tests

`go test ./...` passa sem alterações ao corpus existente após as correcções aos
ficheiros em `test/testdata/`. `config/config_profile_test.go` opera sobre YAML inline
(não depende de `test/testdata/wardex-config.yaml`).

---

## Files Changed

| Ficheiro | Operação | Notas |
|---|---|---|
| `config/config.go` | MODIFIED | Remover structs `Organization`, `ControlWeight`, `Thresholds` e respectivos campos em `Config`. Remover `ReportingConfig.Verbose`. |
| `pkg/model/release.go` | MODIFIED | Remover `AssetContext.DataClass` (linha 21). Manter `Justification` em `CompensatingControl` (audit field, ver acima). |
| `doc/examples/wardex-config.yaml` | REWRITTEN | Schema vivo com campos verificados contra structs. `compensating_controls` usa `type`/`effectiveness`/`justification`. `asset_context` cobre todos os campos consumidos pelo scorer. |
| `test/testdata/wardex-config.yaml` | MODIFIED | Schema correcto em `compensating_controls` e remoção de `data_classification:` orfão. |
| `internal/SPEC_wardex_trust_.md` | ANNOTATED | Adicionar nota próximo da linha 345: o exemplo `domain_weights.technological: "PENDING_APPROVAL"` é histórico — o campo foi removido em v1.9.1; usar `release_gate.risk_appetite` em exemplos futuros. |
| `main.go` (linha 41) | MODIFIED | `Version = "1.9.0"` → `Version = "1.9.1"` |
| `config/config_v191_test.go` | MODIFIED | Estender fixture inline para incluir `data_class: "restricted"` em `release_gate.asset_context`. |
| `config/config_examples_test.go` | NEW | Guard-rail genérica `TestPublishedExamplesMatchSchema`. |
| `CHANGELOG.md` | MODIFIED | Entrada `## [1.9.1] — 2026-05-09` actualizada para listar `data_class` no rol de campos removidos e a guard-rail nova. |
| `doc/releases/v1.9.1-notes.md` | MODIFIED | Release notes corrigidas. |

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
## [1.9.1] — 2026-05-09

### Removed

- `organization` block (`name`, `sector`, `scope`) — never consumed by the scorer
  or by `wardex assess`.
- `domain_weights` map — placeholder for an unshipped feature.
- `control_weights` map — placeholder for an unshipped feature.
- `thresholds` block (`fail_above`, `warn_above`) — duplicated
  `release_gate.warn_above` semantically and was never read. The live failure-on-gap
  flag is `--fail-above` on `wardex evaluate` (CLI), not a YAML field.
- `reporting.verbose` — the CLI flag `--verbose` is the source of truth.
- `release_gate.asset_context.data_class` — declared in `model.AssetContext` but
  never consumed by the scorer (which reads `criticality`, `internet_facing`,
  `requires_auth`, `environment`). Re-introduction with proper scoring semantics
  is deferred to v1.10.x.

### Fixed

- `doc/examples/wardex-config.yaml` rewritten with fields verified against the live
  structs. The previous file in v1.9.0 used a `thresholds:` block with non-existent
  keys; the rewrite mirrors `Config`, `model.AssetContext`, and
  `model.CompensatingControl` exactly.
- `test/testdata/wardex-config.yaml`: `compensating_controls` now uses the correct
  fields (`type`/`effectiveness`/`justification` instead of `id`/`name`/`reduction`);
  `data_classification:` removed (the field was orphan and the spelling was wrong
  for `AssetContext` anyway).

### Added

- `config/config_examples_test.go` (`TestPublishedExamplesMatchSchema`) — strict
  schema validation of `doc/examples/wardex-config.yaml` and
  `test/testdata/wardex-config.yaml` using `yaml.Decoder.KnownFields(true)`. CI
  blocks any release where a published example diverges from the live schema.

### Compatibility

YAML files written for v1.9.0 with the now-removed blocks continue to load without
error in production code paths. The runtime `Load()` continues to accept unknown
fields (Go YAML decoder default) to preserve backward compatibility. No migration
script required.
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

**Q2 — `--strict` para rejeitar campos desconhecidos em runtime?**

Útil em CI de utilizador final: detectaria erros de tipo (`risk_apetite` em vez de
`risk_appetite`). Custo: quebra a backward compatibility de YAMLs antigos. Recomendação
tentativa: introduzir como flag opt-in, off por defeito, em v1.10.x. Implementação:
chamar `decoder.KnownFields(true)` quando a flag estiver activa.

**Q3 — `domain_weights` re-introduzido com semântica real?**

A intenção original (calibração inversa a partir de assessment SAMM/BSIMM/SSDF) faz
sentido conceptualmente mas não faz sentido neste schema sem desenho explícito de
como `domain_weights` interage com `compensating_controls` e `asset_context`. Diferido
até existir caso de uso concreto reproduzível em mais de uma organização.

**Q4 — `data_class` re-introduzido com scoring real?**

Classificação de dados deveria, em princípio, multiplicar criticality (e.g.,
`restricted` ⇒ ×1.3 sobre `Criticality` declarada). O campo ressurge apenas com essa
semântica wireada no scorer e testada. Diferido para v1.10.x.

**Q5 — Consolidação de `AssetContext` e `AssetExposureContext`?**

Existem hoje duas structs com conceitos sobrepostos: `model.AssetContext` (release
gate, com `data_class`) e `model.AssetExposureContext` (asset envelopes, com
`data_classification`). Convenção do resto do projecto é a forma longa
(`data_classification` aparece em READMEs, INPUT_GUIDE, fixtures de assets). Uma
consolidação eliminaria a divergência de spelling e a duplicação conceptual.
Diferido para v1.10.x — é mudança de modelo, não de schema, e merece desenho
dedicado.
