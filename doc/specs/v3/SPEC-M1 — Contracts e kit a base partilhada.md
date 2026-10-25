> **Superseded** — this Portuguese working draft is kept for reference only. The canonical spec is [SPEC-M1-contracts-and-kit.md](SPEC-M1-contracts-and-kit.md).

# SPEC-M1 — Contracts e kit: a base partilhada

Wardex · rascunho 0.2 · 20 de outubro de 2026 · base: baseline/modular-0 (medições em `main` @ `a75500b`)

## 1. Propósito

O módulo 1 cria a base de que todos os outros dependem: `contracts` (tipos puros) e `kit` (primitivas). Fixa também o contrato de saída (`schema_version` e JSON v2 opt-in) e o modelo de erros (exit codes e `Diagnostic`).

A medição mudou o desenho. O `pkg/model` não é um núcleo partilhado: dos 37 tipos, só 3 sobem para `contracts`. `Decision` tem consumidores em três módulos; `AssetContext` e `CompensatingControl` sobem porque o `Config` partilhado os usa. Por D2, `contracts` fica pequeno de propósito, e os outros 34 tipos vão para os módulos donos, cada um no seu módulo (M2, M3 e M4).

## 2. Âmbito

**Dentro:** criar `pkg/contracts` e `pkg/kit`; mover para lá o que tem pelo menos dois módulos consumidores; dividir o `config`; eliminar a cópia triplicada da inicialização CBOR; acrescentar `Diagnostic`, `schema` e `exitcodes.FromError`; a flag `--json-version` no `assess`.

**Fora:** mover os tipos dos donos (M2 a M4); converter os 12 sítios de `ui.*` (cada módulo dono converte os seus); JSON v2 de outros comandos; `kit/reportio` e `kit/canonicalhash` (M2 a M5); validação nova do `config` (D5); a decisão sobre o exit code 2 (M5).

## 3. Decisões herdadas

Globais que se aplicam: D2 (layout, regra dos dois consumidores, divisão do `config`), D3 (JSON v2 opt-in), D4 (`Diagnostic` e erros), D5 (mover não se mistura com acrescentar), D7 (caminho `/v3`, anterior ao M1) e D10 (fusão no fim do módulo).

| # | Decisão do módulo (mandatória) |
| --- | --- |
| M1-D1 | O R1 (`M0#R1`) lê-se «`contracts` não importa pacotes do repositório fora de `pkg/contracts/...`»: os subpacotes de `contracts` importam-se entre si. A mesma leitura vale para o `kit` com `pkg/kit/...` mais `contracts`. O manifesto do M0 tem de ficar assim. |
| M1-D2 | Sobem para `contracts` os tipos com consumidores em mais de um módulo (a facade e os adapters não contam, porque usam a API pública do dono) e os tipos de que um tipo já em `contracts` depende: `Decision` (assess, gate e integrity), e `AssetContext` e `CompensatingControl`, que o `Config` partilhado usa e que o `contracts` não pode importar do gate. |
| M1-D3 | `pkg/duration` e `pkg/utils` não sobem: têm um consumidor cada (`accept/cli` e `orchestrator/gate.go`). Seguem com o gate. |
| M1-D4 | `ApplyProfile` mantém o `io.Writer` injetado e não passa a `Diagnostic`: é um aviso de segurança escrito num destino que o chamador escolhe, e o texto tem de ficar byte a byte igual. |
| M1-D5 | O JSON v2 produz-se por um codificador de reflexão em `contracts/schema`, que dá nomes snake\_case aos campos sem tag e deixa intactas as chaves de mapas. Rejeitado: pós-processador de tokens (corrompe chaves de dados) e DTOs por módulo (duplicam tipos e dessincronizam). |
| M1-D6 | O JSON v2 inclui `diagnostics` (sempre presente, pode ser vazio); o v1 não muda. |
| M1-D7 | `--json-version` só existe nos comandos que suportam v2. No M1 é só o `assess`; nos outros, a flag desconhecida falha como hoje. |
| M1-D8 | O módulo faz-se em duas fases no mesmo branch, em commits separados: M1a só move (golden idêntico) e M1b só acrescenta. |
| M1-D9 | Códigos de `Diagnostic`: `<módulo>.<tema>.<causa>`, em minúsculas, estáveis depois de publicados. |

## 4. Pré-requisitos

- M0 fechado (`baseline/modular-0`), com golden, guarda de fronteiras, pisos e `check-specs` na CI. Estado em 20 de outubro: a tag não existe.
- PR mecânico do caminho `/v3` (D7) fundido: os imports abaixo já usam `github.com/had-nu/wardex/v3/...`. Estado: ainda não fundido.
- `v2.7.0-rc.1` publicada (baseline dos golden). Estado: ainda não publicada.
- O trabalho em curso em `config/config.go` e `internal/policy/loader.go` (B1 e C1, D8) fica fundido na rc.1 antes de o M1 mover o `config`.
- Esta spec pode ser discutida antes; só se implementa depois dos pontos acima.

## 5. Componentes

**Ficha do módulo**

| Linha | Conteúdo |
| --- | --- |
| Entradas | `pkg/exitcodes`, `pkg/cli`, `pkg/atomicwrite`, `config/`, 3 tipos de `pkg/model`, 3 inicializações CBOR (`attest`, `trust`, `internal/cpl`) |
| Saídas | `pkg/contracts` (raiz, `exitcodes`, `config`, `diag`, `schema`), `pkg/kit` (`safeio`, `atomicwrite`, `configio`, `cborcanon`), `ui.RenderDiagnostics`, flag `--json-version` no `assess` |
| API pública | tudo o que está em `pkg/contracts/...` e `pkg/kit/...` (secções 5.2 e 5.3) |
| Dependências permitidas | `contracts`: stdlib. `kit`: stdlib, `gopkg.in/yaml.v3`, a biblioteca CBOR já usada e `contracts` |
| Pacotes absorvidos | `pkg/exitcodes`, `pkg/cli` (passa a `safeio`), `pkg/atomicwrite`, `config`; 3 tipos de `pkg/model` |
| Comandos absorvidos | nenhum (só a flag no `assess`) |
| Branch | `mod/1-contracts` |
| Estimativa | M1a 2 a 3 dias, M1b 2 a 3 dias (minha, a validar; a revisão de 19 de outubro dava 3 a 4 para o M1 inteiro, incluindo o `/v3`, que agora é um PR à parte) |

### 5.1 O que o `pkg/model` é de facto

Medi, para cada um dos 37 tipos, que módulos-alvo o usam fora do próprio `model`. A facade e os adapters não contam como consumidores.

| Dono | Tipos | Quando sai do `model` |
| --- | --- | --- |
| `contracts` (3) | `Decision` (com as constantes), `AssetContext`, `CompensatingControl` | M1a |
| `assess` (19) | os de `asset.go`, `control.go` e `report.go` | M2 |
| `gate` (11) | os de `acceptance.go`, `audit.go`, `epss.go` e 5 de `release.go` (`Vulnerability`, `VulnerabilityEnvelope`, `RiskBreakdown`, `ReleaseDecision`, `GateReport`) | M4 |
| `regulatory` (4) | os de `art14.go` | M3 |

`Decision` tem três módulos consumidores: o gate (`releasegate`, `accept/cli`), o integrity (`statestore`, `cmd/state`) e o assess (`pkg/report`: `html.go`, `markdown.go` e `reader.go` usam o tipo e as constantes). A primeira medição não contava as constantes e só via dois. `AssetContext` e `CompensatingControl` só têm o gate como consumidor, mas sobem na mesma: fazem parte do `Config` (`contracts/config`), que é partilhado, e o `contracts` não pode importar o gate. Sobem por dependência e não pela regra dos dois consumidores. O `AuditEntry` aparece em vários sítios, mas só tem consumidores no gate e em adapters, por isso é do gate. O `report.ReadReport` (`pkg/report/reader.go`, com a assinatura `ReadReport(path string, maxAgeHours int) ([]model.Vulnerability, string, error)`) devolve um tipo do gate: é provável que o leitor viva no `pkg/report` por engano (a confirmar nas specs do M2 e do M4).

Durante a migração, `pkg/model` mantém os 3 tipos movidos como aliases (`type Decision = contracts.Decision`), para os 68 ficheiros de produção e 42 de teste que o importam continuarem a compilar sem edição. Os aliases saem quando o último dono migrar.

### 5.2 `pkg/contracts`

- **`contracts` (raiz):** `Decision` e as constantes `DecisionAllow`, `DecisionBlock` e `DecisionWarn` (valores `allow`, `block` e `warn`), `AssetContext`, `CompensatingControl`.
- **`contracts/exitcodes`:** `git mv` de `pkg/exitcodes`, com o teste de contrato (que lê o código-fonte do próprio pacote). Constantes inalteradas: 0, 1, 3, 4, 5, 6, 10, 11, 12 e 13. Acrescenta-se `FromError` (secção 6).
- **`contracts/config`:** tipos (`Config`, as suas secções e `Profile`), `Defaults()` (extraído do `Load`), `MigrateConfig`, `CurrentConfigSchemaVersion`, `DefaultForcedUpgradeTripwireFailures` e `Tripwire()`. Sem I/O e sem variáveis de ambiente.
- **`contracts/diag`:** `Diagnostic` (secção 5.5).
- **`contracts/schema`:** versões do contrato de saída e codificador v2 (secção 5.6).

### 5.3 `pkg/kit`

- **`kit/safeio`:** o `pkg/cli` atual, renomeado. Contém E/S segura de caminhos (`ValidateInputPath`, `ValidateOutputPath`, `SafePath`, `SafeOutputPath`, `SafeReadFile`, `SafeOpenFile`, `SafeWriteFile`, `ReadFile` e os erros `ErrPathTraversal`, `ErrAbsolutePath` e `ErrInvalidPath`). O nome `cli` induzia em erro. Os testes e os fuzz movem-se com ele.
- **`kit/atomicwrite`:** `Write` e `WriteWithContext`. Consumidores: `accept/store` (gate), `statestore` (integrity) e o `safeio`.
- **`kit/configio`:** `Load` (leitura com `safeio`, descodificação estrita com `KnownFields(true)`, `MigrateConfig` e defaults quando o ficheiro não existe) e `ApplyProfile`, com `getActor` (lê `WARDEX_ACTOR`, `GITHUB_ACTOR` e `USER`).
- **`kit/cborcanon`:** o modo CBOR canónico, hoje inicializado três vezes de forma idêntica (`pkg/attest`, `pkg/trust` e `internal/cpl`), cada uma com o seu `panic` no `init`. Passa a haver uma só, com o mesmo comportamento de falha rápida.

### 5.4 Divisão do `config`

O `Config` é uma struct única com secções de vários donos (`ReleaseGate`, `AcceptanceConfig`, `Art14Config`, `StateStoreConfig` e `ProvenanceConfig`, entre outras), usada por todas as áreas. Fica como tipo partilhado (D2), e o que faz I/O sai para o `kit/configio`.

| Hoje (`config/`) | Depois |
| --- | --- |
| tipos, `Tripwire()`, constantes | `contracts/config` |
| `MigrateConfig`, `migrateV1ToV2` | `contracts/config` (puros) |
| valores por omissão (literal dentro do `Load`) | `contracts/config.Defaults()` |
| `Load`, 17 chamadas | `kit/configio.Load` |
| `ApplyProfile`, 2 chamadas, e `getActor` | `kit/configio` |

Não existe hoje validação para além da descodificação estrita; não se acrescenta no M1 (D5).

### 5.5 `Diagnostic`

```go
type Severity string // «info» ou «warn»

type Diagnostic struct {
    Severity Severity
    Code     string            // <módulo>.<tema>.<causa>
    Message  string            // texto atual, para o stderr ficar igual
    Context  map[string]string // dados estruturados para o JSON v2
}
```

Os avisos passam a viajar no resultado em vez de serem escritos por `ui.Warnf`. No M1 entram o tipo e o renderizador `ui.RenderDiagnostics`, que escreve cada diagnóstico pelo mesmo logger e com o mesmo texto e nível de hoje. A conversão dos sítios faz-se nos módulos donos. Inventário atual (12 sítios, 9 `warn` e 3 `info`):

| Sítio | Sev. | Código proposto | Converte em |
| --- | --- | --- | --- |
| `snapshot/delta.go:26` | warn | `assess.snapshot.control_not_in_previous` | M2 |
| `analyzer/gap.go:34` | warn | `assess.mapping.unknown_control` | M2 |
| `art14/art14gen.go:235` | warn | `regulatory.art14.malformed_artefact_skipped` | M3 |
| `gate/pipeline.go:125` | info | `gate.enisa.stub_backend` | M4 |
| `sboms/cyclonedx.go:70` | info | `gate.sbom.vex_state_ignored` | M4 |
| `sboms/cyclonedx.go:130` | warn | `gate.sbom.empty_id_skipped` | M4 |
| `sboms/cyclonedx.go:133` | warn | `gate.sbom.no_cvss_skipped` | M4 |
| `sboms/openvex.go:75` | warn | `gate.sbom.unrecognized_state_skipped` | M4 |
| `epss/client.go:124` | warn | `gate.epss.malformed_skipped` | M4 |
| `epss/client.go:127` | warn | `gate.epss.out_of_range_skipped` | M4 |
| `trust/store.go:280` | warn | `integrity.trust.admin_key_decode_failed` | M5 |
| `statestore/store.go:236` | info | `integrity.statestore.history_cleaned` | M5 |

Até cada módulo converter os seus sítios, o `diagnostics` do JSON v2 não leva esses avisos, que continuam no stderr.

### 5.6 Contrato de saída: `schema` e JSON v2

- **v1** não muda nem ganha `schema_version`: seria uma alteração visível para quem o consome.
- **v2** é opt-in (`--json-version v2`) e acrescenta `schema_version: 2` e `diagnostics` no topo. As chaves de struct passam a snake\_case (`GapReasons` dá `gap_reasons`; siglas como `CVSSScore` dão `cvss_score`), as tags `json` já existentes mantêm-se e as chaves de mapas não se tocam.
- `contracts/schema` expõe `Version` (`V1` e `V2`), `Parse` e `MarshalV2`. O `assess` é o único emissor v2 no M1.
- **Verificação:** um teste de conformidade garante, para cada golden v2, que o conjunto de chaves é o do v1 convertido para snake\_case (com uma lista explícita das chaves de dados que ficam de fora) e que todas as chaves casam `^[a-z][a-z0-9_]*$`.
- O valor das enumerações (`Covered`, `Partial`, `Gap`) fica verbatim no v2 (proposta minha; a ADR-003 fixa). Converter os valores é uma segunda decisão.

## 6. Modelo de erros

- **Exit codes.** O contrato numérico mantém-se: 0, 1, 3, 4, 5, 6, 10, 11, 12 e 13. O 2 está reservado (POSIX) e, pelo teste de contrato, nunca é produzido.
- **`FromError(err) int`.** Usa `errors.Is` sobre sentinelas definidas em `exitcodes`: `ErrIntegrity` (3), `ErrStoreInconsistent` (4), `ErrGateBlocked` (10), `ErrComplianceFail` (11), `ErrActivelyExploited` (12) e `ErrDuplicateRelease` (13). Qualquer outro erro dá 1 e `nil` dá 0. Os códigos 5 e 6 não são erros (avisos operacionais) e continuam a ser devolvidos pelos comandos que os calculam. Cada módulo adota as sentinelas ao migrar, e o `main` passa a usar `FromError`.
- **Avisos recuperáveis** são `Diagnostic`; erros continuam a ser `error`.
- **Incoerência conhecida.** O `cmd/audit` termina com o literal `2` em 4 sítios (`verify_link.go` e `verify_chain.go`), e o `EXIT_CODES.md` documenta esse 2 para o CPL, mas o teste de `exitcodes` declara o 2 reservado e nunca produzido. O teste só lê `exitcodes.go`: não lê o `EXIT_CODES.md` nem os comandos, por isso não apanha esta incoerência. O M1 não muda nada (D5): fica como `known_defect` no golden do G8 e decide-se na spec do M5. Opções: nomear o 2 e documentar a exceção; passar a 1 (quebra quem usa o código documentado); manter.

## 7. Uso isolado

```go
cfg, err := configio.Load("wardex-config.yaml") // kit/configio
data, err := safeio.SafeReadFile(path)          // kit/safeio
out, err := schema.MarshalV2(result, diags)     // contracts/schema
os.Exit(exitcodes.FromError(err))               // contracts/exitcodes
```

Os imports usam `github.com/had-nu/wardex/v3/pkg/...`. O `contracts` e o `kit` compilam e testam-se sozinhos, sem o resto do repositório: `go test ./pkg/contracts/... ./pkg/kit/...`.

## 8. Plano de testes

- **Golden G1 a G10 e matriz do G1:** idênticos no fim da M1a (o `git diff` de `want/` é vazio nesse commit).
- **Golden v2 novos** do `assess` (iso27001 e gdpr), com o trailer `Golden-Change: M1-P9`, mais a asserção de snake\_case.
- **Conformidade v1 e v2** (secção 5.6).
- **`cborcanon`:** vetores CBOR fixos gerados antes da mudança, comparados byte a byte com a saída de cada um dos três consumidores.
- **`schema`:** tabela de nomes (`ID` dá `id`, `CVSSScore` dá `cvss_score`, `GapReasons` dá `gap_reasons`, `EPSSEnrichment` dá `epss_enrichment`) e fuzz com a propriedade «idempotente e sem pânico».
- **`ui.RenderDiagnostics`:** a saída é byte a byte igual à de `ui.Warnf` e `ui.Infof` para a mesma mensagem.
- **`FromError`:** tabela erro → código, incluindo erros embrulhados.
- **Movidos:** os testes e fuzz do `safeio`, o teste de contrato do `exitcodes` e os 5 testes do `config` mantêm-se verdes.
- **Sensibilidade (≥ 4 de 5):** (m1) trocar uma constante de exit code; (m2) alterar a lógica de autorização do `ApplyProfile`; (m3) mudar o `Mode` por omissão do `Defaults()`; (m4) trocar uma opção CBOR canónica; (m5) estragar a conversão de siglas no snake\_case.

## 9. Plano de migração

| Passo | Trabalho | Critério de aceitação |
| --- | --- | --- |
| M1-P1 | Criar `pkg/contracts` e `pkg/kit` no manifesto, sem código | guarda de fronteiras verde |
| M1-P2 | `pkg/exitcodes` → `pkg/contracts/exitcodes` (9 ficheiros de produção e 8 de teste importam-no) | golden idêntico; teste de contrato verde |
| M1-P3 | `pkg/atomicwrite` → `kit/atomicwrite`; `pkg/cli` → `kit/safeio` (54 ficheiros de produção e 2 de teste, 78 referências), com ferramenta que entende Go | build, `vet`, testes e fuzz verdes; golden idêntico |
| M1-P4 | `Decision`, `AssetContext` e `CompensatingControl` → `contracts`, com aliases no `model` | golden idêntico |
| M1-P5 | `config` → `contracts/config` + `kit/configio` (17 `Load`, 2 `ApplyProfile`, 16 + 4 importadores); extrair `Defaults()` | golden G3 e G7 idênticos; 5 testes do `config` verdes |
| M1-P6 | `kit/cborcanon` e troca nos três sítios | vetores CBOR iguais; G7 a G9 idênticos |
| M1-P7 | Fim da M1a: atualizar a baseline de fronteiras | entradas dos pacotes movidos removidas; `config/` fora do R7 |
| M1-P8 | `contracts/diag` + `ui.RenderDiagnostics` | teste de equivalência verde |
| M1-P9 | `contracts/schema` + `--json-version` no `assess` + golden v2 | conformidade v1 e v2 verde; v1 intocado |
| M1-P10 | `exitcodes.FromError` e sentinelas; o `main` usa-as | exit codes idênticos em G3 e G8 |
| M1-P11 | Fecho: definição de pronto, revisão das ADR-003 e ADR-004 com o que a implementação mostrou, tag `baseline/modular-1` | secção 10 |

Dependências: P3 antes de P5 (o `configio` usa o `safeio`); P4 antes de P5 (o `config` usa dois dos tipos); P8 antes de P9 (o v2 leva `diagnostics`); P2 a P6 são mecânicos, com golden idêntico. Os renomeamentos fazem-se com ferramenta que entenda Go, não com `sed`.

## 10. Definição de pronto

- Golden G1 a G10 e matriz do G1 idênticos no commit de fim da M1a; v1 intocado no fim do módulo.
- Golden v2 do `assess` (iso27001 e gdpr) verdes e conformidade v1 e v2 verde.
- Guarda de fronteiras: `contracts` e `kit` cumprem o R1 e o R2; a baseline já não tem entradas de `pkg/exitcodes`, `pkg/cli`, `pkg/atomicwrite` nem `config/`.
- `pkg/exitcodes`, `pkg/cli`, `pkg/atomicwrite` e `config/` deixam de existir, sem stubs; `pkg/model` só mantém os 3 aliases documentados.
- Cobertura por pacote: código movido ≥ 60 %, código novo (`diag`, `schema`, `cborcanon`, `FromError`) ≥ 80 %; pisos atualizados.
- Nenhum `#nosec` sem justificação nem `_ =` novo nos pacotes de `contracts` e `kit`; `funlen` e `forbidigo` sem entradas neles.
- Vetores CBOR iguais antes e depois; sensibilidade ≥ 4 de 5.
- ADR-003 e ADR-004 revistas com o que a implementação mostrou; esta spec passa no `check-specs`.
- Tag `baseline/modular-1` criada e branch fundido em `main` (D10).

## 11. Riscos

- **Renomear `pkg/cli` para `safeio` em 54 ficheiros** colide com os pacotes `accept/cli` e `enrich/cli`, também chamados `cli`. Mitigação: ferramenta que entende Go e compilação verificada por passo.
- **Importar `config` como `config`** choca com variáveis locais com o mesmo nome. Mitigação: alias de import onde for preciso.
- **O codificador de reflexão** falha com tipos que implementam `MarshalJSON`, structs embebidas ou `omitempty`. Mitigação: v2 só no `assess`, teste de conformidade e alargamento módulo a módulo.
- **A ordem do stderr muda** quando os módulos donos converterem os sítios (os avisos passam a sair depois da chamada). Mitigação: um golden com avisos por módulo e o renderizador chamado no mesmo ponto lógico.
- **Aliases em `pkg/model`** escondem dependências. Mitigação: entradas na baseline e remoção no último dono.
- **O `contracts` é o primeiro API público estável.** Mitigação: ver «Não verificado» sobre o nível de estabilidade.
- **Mover o CBOR para o `kit`** muda o sítio do `panic` no `init`. Mitigação: manter a falha rápida e o teste de vetores.

## 12. Não verificado

- Os campos completos de `CatalogControl` e a forma exata de `GapReport`: só vi o `Finding`. Está confirmado que não há `MarshalJSON` em `pkg/`, `cmd/`, `internal/` nem `config/`.
- Se o `report.ReadReport` pertence ao gate e dispensa o `kit/reportio` (D2): a localização e a assinatura estão confirmadas, a decisão fica para as specs do M2 e do M4.
- Se a ordem do stderr se mantém quando os módulos donos converterem os sítios (só se aplica depois do M1).
- A convenção de nível de estabilidade para pacotes públicos (por exemplo `Stability:` no doc do pacote): D2 não a define e a ADR-002 pode cobri-la.
- Se `pkg/duration` e `pkg/utils` ficam no gate ou na facade: o consumidor único de cada um está confirmado; o destino fecha-se nas specs do M4 e do M7.
- O estado do trabalho em curso na máquina do autor (`config/config.go`, `internal/policy/loader.go` e os testes associados): não o vi. A spec assume que não colide com o M1 e confirma-se antes de começar.
- As medições vêm de `main` @ `a75500b`; depois do `/v3` e da rc.1 têm de se repetir (contagens e números de linha dos 12 sítios podem mudar).
