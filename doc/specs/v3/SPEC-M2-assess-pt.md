# SPEC-M2 — Assess: avaliação de conformidade

Wardex · rascunho 0.1 · 23 de outubro de 2026 · base: v2.7.0-rc.1 (`5d8c420`, medições no remoto público)

## 1. Propósito

O módulo 2 isola a avaliação de conformidade: ingestão de controlos e ativos, catálogos, correlação, análise de lacunas, pontuação, snapshots e relatórios. No fim, `pkg/assess` compila, testa-se e usa-se sozinho, sem gate, regulatory nem integrity, e é a base onde o AIPD se constrói (D9).

A medição mostra que o corte é limpo, com quatro pontos que a spec tem de fechar:

1. Nenhum módulo futuro importa pacotes do assess, com uma exceção: o `pkg/accept` (gate) importa o `pkg/report` só para o `ReadReport`. Os restantes consumidores são adaptadores, o `orchestrator` e o `sdk`.
2. O `GapReport` embute o `GateReport`, um tipo do gate (secção 5.2). É o ponto mais sensível e contradiz a tabela 5.1 da SPEC-M1.
3. O `pkg/report` mistura os escritores (assess) com o `ReadReport` (gate) (secção 5.3).
4. O `internal/policy` não é acessível aos adaptadores, e o `cmd/policy` importa-o hoje (secção 5.4).

## 2. Âmbito

**Dentro:** criar `pkg/assess`; mover para lá os 8 pacotes e os 19 tipos do `pkg/model` da secção 5.1; expor a API pública; converter `cmd/assess`, `cmd/policy`, `cmd/assets`, `cmd/evaluate` (só o uso de `FormatList` e `IsSupportedFormat`), o `main.go` da raiz, o `orchestrator` e o `sdk` para essa API; converter os dois `ui.Warnf` do assess em `Diagnostic`; registar o serviço na facade.

**Fora:** o AIPD e a unificação do `internal/policy` com o `pkg/ingestion` (D9); renomear `frameworks/` (M2-D7); mover o `ReadReport` (M4); `kit/reportio` (M2-D4); JSON v2 de outros comandos; validação nova de catálogos ou de controlos (D5); qualquer stub para módulos seguintes.

## 3. Decisões herdadas

Globais que se aplicam: D1 (ordem), D2 (layout e regra dos dois consumidores), D3 (JSON v2 opt-in), D4 (`Diagnostic` e erros), D5 (mover não se mistura com acrescentar), D9 (o M2 só relocaliza o `internal/policy` e expõe o serviço na facade) e D10 (fusão no fim do módulo).

| # | Decisão do módulo (proposta; fecha com a aceitação desta spec) |
| --- | --- |
| M2-D1 | O `GateReport` e os tipos de que depende sobem para `contracts`. Medido: `ExecutiveSummary.GateSummary` e `GapReport.Gate` são `*GateReport`; os escritores (csv, html, markdown) e o `snapshot/delta.go` leem `OverallDecision`, `GateMaturityLevel` e `Decisions` (`[]ReleaseDecision`). Pela regra dos dois consumidores (M1-D2) o `GateReport` tem consumidores no assess e no gate, por isso sobe, com o `ReleaseDecision` e o que este exigir. Rejeitado: DTO do assess (duplica tipos, M1-D5) e campo opaco (perde tipagem e arrisca o JSON v1). Recomendo fazer a subida no M1-P4, porque o M1 ainda não começou e a tabela 5.1 da SPEC-M1 atribui estes tipos ao gate; se o M1 fechar antes, faz-se no M2-P1. |
| M2-D2 | O `ReadReport` não se move no M2. O `pkg/report/reader.go` fica em `pkg/report` (entrada legacy) até ao M4 e o resto do pacote sai. Como lê o formato do relatório sem importar o `assess` fica para a spec do M4; o M2 só garante que compila e se comporta igual. |
| M2-D3 | Os dois avisos do assess (`analyzer/gap.go:34` e `snapshot/delta.go:26`) passam a `Diagnostic` com os códigos da SPEC-M1 (`assess.mapping.unknown_control` e `assess.snapshot.control_not_in_previous`). Viajam num campo `Diagnostics` do resultado da análise, e não no `GapReport`, para o JSON v1 não mudar. O adaptador imprime-os com `ui.RenderDiagnostics` e o JSON v2 inclui-os. |
| M2-D4 | O `kit/reportio` não se cria no M2. Nenhum segundo módulo consome os escritores: o `cmd/evaluate` e o `main.go` só usam `FormatList` e `IsSupportedFormat`. Reavalia-se quando o AIPD for o segundo consumidor. |
| M2-D5 | Só `pkg/assess` é API pública; a implementação fica em `pkg/assess/internal/`. Os adaptadores e a facade usam a API pública, incluindo `catalog.Keys`, `FormatList`, `IsSupportedFormat` e o serviço de política. O `internal/policy` passa a `pkg/assess/internal/policy`, inacessível aos adaptadores. |
| M2-D6 | Os 19 tipos movem-se juntos para `pkg/assess` e o `pkg/model` mantém aliases para eles. O `pkg/assess` não pode importar o `pkg/model` (ciclo), por isso nenhum código movido pode ficar a depender do `model`. Os aliases saem quando o último dono migrar. |
| M2-D7 | `frameworks/` não se renomeia nem se move: lê-se por caminho em tempo de execução (o `cmd/policy` e a ajuda do `cmd/evaluate` apontam para `./frameworks/...`) e não é embebido. A hipótese `policies/` decide-se com a unificação do policy (D9), depois da modularização. |
| M2-D8 | Duas fases no mesmo branch, em commits separados (como M1-D8): M2a só move (golden idêntico) e M2b só acrescenta (diagnósticos e serviço na facade). |

## 4. Pré-requisitos

- M1 fechado (`baseline/modular-1`), com `contracts` (incluindo `Decision`, `AssetContext`, `CompensatingControl`, `Diagnostic`, `schema` e `config`) e `kit` (`safeio`, `configio` e `atomicwrite`).
- M2-D1 resolvido: `GateReport` em `contracts`, no M1-P4 ou no M2-P1.
- Caso golden de `assess --gate` no G1 (secção 8). Sem ele, o M2-D1 mexe num campo sem rede de segurança.
- Medições repetidas sobre `baseline/modular-1`: as desta spec vêm da `v2.7.0-rc.1` e as contagens e números de linha podem mudar.
- Estado do remoto e da CI esclarecido (D10): os testes golden, a guarda de fronteiras e os pisos só valem como critério se correrem na CI.
- Esboço da `SPEC-X-aipd` lido antes de fechar a API (secção 5.6).

## 5. Componentes

**Ficha do módulo**

| Linha | Conteúdo |
| --- | --- |
| Entradas | `pkg/analyzer`, `pkg/catalog` (7 catálogos YAML embebidos), `pkg/correlator`, `pkg/ingestion`, `pkg/report` (sem o `reader.go`), `pkg/snapshot`, `pkg/scorer`, `internal/policy`, 19 tipos de `pkg/model` e, se o M2-D1 recair aqui, o `GateReport` com as suas dependências |
| Saídas | `pkg/assess` (API pública), `pkg/assess/internal/{analyzer,catalog,correlator,ingestion,report,snapshot,scorer,policy}`, serviço na facade, comandos convertidos para a API pública, campo `Diagnostics` no resultado da análise |
| API pública | tudo o que está em `pkg/assess` (secções 5.1 e 7) |
| Dependências permitidas | stdlib, as bibliotecas que os pacotes movidos já usam (a confirmar), `contracts` e `kit` |
| Pacotes absorvidos | os 8 da tabela 5.1 (cerca de 2 500 linhas de produção) e 19 tipos de `pkg/model` |
| Comandos absorvidos | `assess`, `policy` e `assets` (este a confirmar, secção 5.4) |
| Branch | `mod/2-assess` |
| Estimativa | M2a 3 a 4 dias, M2b 1 a 2 (minha, a validar; a D11 dava 4 a 5 para o M2 inteiro, sem validação) |

### 5.1 O que se absorve (medido)

| Pacote | Produção (linhas) | Consumidores fora do módulo | Destino |
| --- | --- | --- | --- |
| `pkg/analyzer` | 393 | `cmd/assess`, `orchestrator`, `sdk` | `assess/internal/analyzer` |
| `pkg/catalog` (e 7 YAML) | 99 | `main.go`, `cmd/assess`, `orchestrator`, `report`, `sdk` | `assess/internal/catalog` |
| `pkg/correlator` | 140 | `cmd/assess`, `orchestrator`, `sdk` | `assess/internal/correlator` |
| `pkg/ingestion` | 453 | `cmd/assess`, `orchestrator` (2 sítios), `sdk` | `assess/internal/ingestion` |
| `pkg/report` | 830 | `main.go`, `cmd/assess`, `cmd/evaluate`, `pkg/accept`, `orchestrator`, `sdk` | `assess/internal/report` (sem `reader.go`) |
| `pkg/snapshot` | 101 | `cmd/assess`, `orchestrator`, `sdk` | `assess/internal/snapshot` |
| `pkg/scorer` | 238 | `cmd/assess`, `pkg/analyzer` | `assess/internal/scorer` |
| `internal/policy` | 243 | `cmd/policy` | `assess/internal/policy` |

Os 19 tipos são os de `asset.go` (6: `Asset`, `AssetExposureContext`, `AssetThreat`, `AssetCompensatingControl`, `AssetCompliance`, `LayerDelta`), `control.go` (6: `ControlLayer`, `ExistingControl`, `CatalogControl`, `Practice`, `Evidence`, `Mapping`) e `report.go` (7: `CoverageStatus`, `GatePracticeStatus`, `Finding`, `DomainSummary`, `ExecutiveSummary`, `Delta`, `GapReport`). Fora do assess, só o `orchestrator`, o `sdk`, os adaptadores e os exemplos os usam, com a exceção do `GateReport` dentro do `GapReport` (5.2).

O `orchestrator` importa 6 destes pacotes (`analyzer`, `catalog`, `correlator`, `ingestion`, `report` e `snapshot`) e passa a importar só o `pkg/assess`. A baseline de fronteiras perde essas entradas.

### 5.2 O GateReport dentro do GapReport

`ExecutiveSummary.GateSummary` (`pkg/model/report.go:71`) e `GapReport.Gate` (`:89`) são `*GateReport`, tipo definido em `release.go` com `Decision`, `ReleaseDecision` e contadores. Quem o lê no lado do assess: `report/csv.go`, `html.go`, `markdown.go`, `snapshot/delta.go` e o template `report.html` (que usa a decisão, a maturidade e a lista de decisões). Quem o preenche: `orchestrator/evaluation.go:317`. O `cmd/aggregate` e o `report/reader.go` também o leem, mas do lado do gate.

A SPEC-M1 (5.1) atribui o `GateReport` e outros 10 tipos ao gate (M4). A medição do M1 contou identificadores `model.X` fora do `model`, e por isso não apanhou o acesso por campo nos escritores. Pela regra do próprio M1-D2, o `GateReport` tem dois módulos consumidores. O M2-D1 propõe subi-lo, e a SPEC-M1 deve ser corrigida em conformidade (tabela 5.1 e passo M1-P4). O fecho de dependências do `ReleaseDecision` (`Vulnerability`, `RiskBreakdown`, ...) mede-se antes de decidir quantos tipos sobem.

O JSON v1 não pode mudar: as chaves `Gate`, `GateSummary` e `Decisions` mantêm-se byte a byte, e é isso que o caso golden de `assess --gate` congela.

### 5.3 Divisão do pkg/report

Escritores (`csv`, `html`, `json`, `markdown`, `title` e `templates/report.html`, embebido por `go:embed`) vão para o assess. O `reader.go` (`ReadReport`, que devolve `[]model.Vulnerability` e o hash do relatório) tem um só consumidor, o `pkg/accept`, que o re-exporta ao `accept/cli`. Fica em `pkg/report` como entrada legacy até ao M4 (M2-D2).

### 5.4 internal/policy e cmd/policy

O `cmd/policy` (`validate`, `list`, `check-expiry` e `add`) importa `internal/policy`, `pkg/cli`, `pkg/exitcodes` e `pkg/ui`. Como `pkg/assess/internal/policy` não é acessível aos adaptadores, o M2 expõe na API pública as operações que o comando usa. O texto, os exit codes e o `exit_test.go` ficam idênticos.

O `cmd/assets` (inventário de ativos ICT) importa só `pkg/cli` e `pkg/ui`, e o `LoadAssets` vive no `ingestion`. Propõe-se absorvê-lo no assess; a confirmar com o autor.

### 5.5 Diagnósticos

| Sítio | Sev. | Código | Passo |
| --- | --- | --- | --- |
| `analyzer/gap.go:34` | warn | `assess.mapping.unknown_control` | M2-P12 |
| `snapshot/delta.go:26` | warn | `assess.snapshot.control_not_in_previous` | M2-P12 |

Até ao M2-P12 os dois `ui.Warnf` ficam como entradas `allow: [pkg/ui]` na baseline de fronteiras (R4). Depois, o resultado leva `Diagnostics`, o adaptador imprime-os no mesmo ponto lógico e o JSON v2 passa a incluí-los.

### 5.6 O que o M2 deixa pronto para o AIPD

O M2 não acrescenta nada de AIPD (D5, D9) e não deixa stubs. Deixa três factos, medidos, para a `SPEC-X-aipd`:

- O GDPR.35 e as suas cinco práticas vivem no catálogo, que passa a `assess/internal/catalog`. As práticas têm `gate_relevant: false` e o `Finding` só leva `GatePractice` para controlos com práticas de gate, pelo que o assess provavelmente não as discrimina hoje (a confirmar).
- O `model` não tem o conceito de tratamento (finalidade, categorias de dados, titulares, base de licitude).
- Pergunta em aberto: o AIPD é um subpacote do assess ou um módulo próprio? Um módulo próprio só vê `contracts` e `kit` (R2), por isso os `Finding` teriam de subir para `contracts` ou a facade compõe. O D9 diz «pacote novo e aditivo». O M2 não decide, mas não esconde `Finding` e `CatalogControl` atrás de `internal/`.

## 6. Modelo de erros

- Sem exit codes novos. O M2 adota as sentinelas que o assess já produz (SPEC-M1, secção 6), levantadas com os golden do G1 e do G2 (exit code por caso).
- Os avisos recuperáveis passam a `Diagnostic` (5.5); os erros continuam `error`.
- O `exit_test.go` do `cmd/policy` mantém-se idêntico.

## 7. Uso isolado

```go
controls, err := assess.LoadControls("controls.yaml")
res, err := assess.Analyze(controls, "gdpr")
err = assess.Report(res, "markdown", "report.md", 10)
```

Os nomes vêm do `pkg/sdk/assess.go` atual (`LoadControls`, `Analyze`, `Report`) e são propostos; a facade mantém a assinatura pública do SDK. Na linha de comandos: `wardex assess documented.yaml implemented.yaml --framework gdpr --output json`. O módulo testa-se sozinho com `go test ./pkg/assess/...`, sem o resto do repositório.

## 8. Plano de testes

- **Golden G1 (matriz completa, incluindo gdpr), G2 e G10:** idênticos no fim da M2a, com o `git diff` de `want/` vazio.
- **Caso novo de `assess --gate` no G1:** acrescentado antes do primeiro passo de movimentação, com o código ainda intacto, para congelar o JSON v1 com `Gate`.
- **Golden v2 do assess (M1-P9) e conformidade v1 e v2:** continuam verdes sobre os tipos movidos; o codificador por reflexão não pode falhar com os tipos embebidos.
- **Golden de stderr com os dois avisos:** texto e nível iguais antes e depois da M2b.
- **Movidos:** testes, fuzz e benchmarks do `ingestion` (`FuzzParseYAML`, `FuzzParseJSON`, `FuzzParseCSV`), os testes dos 7 catálogos e o `exit_test.go` do `cmd/policy`.
- **Fronteiras:** `pkg/assess` só importa `contracts` e `kit`; não importa `pkg/model` (M2-D6).
- **Sensibilidade (≥ 4 de 5):** (m1) o limiar de maturidade da cobertura; (m2) a derivação de `Domains` a partir de `Domain` no loader do catálogo (P0.2); (m3) remover `layer_delta` do JSON; (m4) inverter a ordem do roadmap; (m5) mudar a forma do campo `Gate` nos escritores.

## 9. Plano de migração

| Passo | Trabalho | Critério de aceitação |
| --- | --- | --- |
| M2-P1 | Subir `GateReport` e dependências para `contracts`, com aliases no `model` (só se não foi feito no M1-P4) | golden idêntico, incluindo o caso `assess --gate` |
| M2-P2 | Criar `pkg/assess` no manifesto, sem código | guarda de fronteiras verde |
| M2-P3 | 19 tipos → `pkg/assess`, com aliases no `model` | golden idêntico; sem ciclo de imports |
| M2-P4 | `pkg/catalog` e os 7 YAML → `assess/internal/catalog` | G1 de todos os frameworks idêntico |
| M2-P5 | `pkg/scorer` e `pkg/correlator` → `internal/` | golden idêntico; testes verdes |
| M2-P6 | `pkg/analyzer` → `internal/` | golden idêntico; `ui.Warnf` registado na baseline |
| M2-P7 | `pkg/ingestion` → `internal/` | fuzz e benchmarks verdes |
| M2-P8 | `pkg/snapshot` → `internal/` | G2 idêntico |
| M2-P9 | Escritores do `pkg/report` e `templates/report.html` → `internal/report` (sem `reader.go`) | todos os formatos do G1 idênticos; `reader.go` compila |
| M2-P10 | `internal/policy` → `assess/internal/policy` | G10 idêntico; `exit_test.go` verde |
| M2-P11 | API pública `pkg/assess`; converter `cmd/assess`, `cmd/policy`, `cmd/assets`, `cmd/evaluate`, `main.go`, `orchestrator` e `sdk`; atualizar a baseline de fronteiras (fim da M2a) | golden G1, G2 e G10 idênticos; entradas dos pacotes movidos removidas |
| M2-P12 | Os dois `Diagnostic` e o campo `Diagnostics` no resultado, com o golden de stderr | equivalência de texto e nível; JSON v2 com `diagnostics` |
| M2-P13 | Serviço do assess na facade | `examples/sdk` compila sem edição |
| M2-P14 | Fecho: definição de pronto, revisão das ADR com o que a implementação mostrou, correção da SPEC-M1 5.1, tag `baseline/modular-2` | secção 10 |

Dependências: P1 antes de P3; P3 antes de P4 a P10; P4 e P5 antes de P6 (o analyzer usa catálogo, scorer e correlator); P3 e P4 antes de P9 (os escritores usam o catálogo); P11 depois de P4 a P10; P12 depois de P11. O ritmo é o do M1: P1 a P11 mecânicos, com golden idêntico e ferramenta que entende Go (não `sed`).

## 10. Definição de pronto

- Golden G1 (matriz completa), G2 e G10 idênticos no commit de fim da M2a; v1 intocado no fim do módulo.
- Caso `assess --gate` no G1 e golden v2 verdes; conformidade v1 e v2 verde.
- Guarda de fronteiras: `pkg/assess` cumpre o R1 e o R2 (só `contracts` e `kit`), e a baseline já não tem entradas dos 8 pacotes movidos nem as do `orchestrator` para eles.
- Os 8 pacotes e o `internal/policy` deixam de existir nos sítios antigos, sem stubs, exceto o `pkg/report/reader.go` (M2-D2). O `pkg/model` só mantém os aliases documentados.
- Cobertura por pacote: código movido ≥ 60 %, código novo (`Diagnostics`, serviço da facade) ≥ 80 %; pisos atualizados.
- Nenhum `#nosec` sem justificação nem `_ =` novo em `pkg/assess`; `funlen` e `forbidigo` sem entradas.
- Sensibilidade ≥ 4 de 5.
- API pública revista contra o esboço da `SPEC-X-aipd` (5.6).
- ADR-002 e ADR-004 revistas; SPEC-M1 corrigida (5.2); esta spec passa no `check-specs`.
- Tag `baseline/modular-2` criada e branch fundido em `main` (D10).

## 11. Riscos

- **JSON v1 com `Gate` sem caso golden.** Mitigação: caso novo antes de qualquer movimentação.
- **Ciclo de imports entre `pkg/assess` e `pkg/model`.** Os aliases apontam para `assess`, por isso o código movido não pode importar o `model`. Mitigação: mover os 19 tipos juntos (P3) e compilar a cada passo.
- **O `GateReport` arrasta tipos do gate para `contracts`.** `contracts` cresce para além dos 3 tipos do M1. Mitigação: medir o fecho de dependências antes e registar a exceção na ADR-002.
- **Reescrever os imports do `orchestrator` (6 pacotes).** Mitigação: um passo próprio (P11) e golden por comando.
- **`pkg/report` dividido.** O `reader.go` depende do formato do `GapReport` sem poder importar o `assess`. Mitigação: fica legacy e resolve-se no M4.
- **Catálogos embebidos.** O `go:embed *.yaml` tem de mover-se com o pacote sem alterar o resultado de nenhum framework. Mitigação: G1 de todos os frameworks em cada passo.
- **Ordem do stderr** quando os avisos passarem a sair depois da chamada (M1, riscos). Mitigação: golden de stderr e renderizador chamado no mesmo ponto lógico.
- **Desenhar o assess a pensar no AIPD.** Mitigação: D5 e D9; só se mantêm os tipos acessíveis (5.6).

## 12. Não verificado

- A cobertura real e a execução dos testes: não havia Go na sandbox, por isso nenhum teste foi executado nesta análise.
- As medições vêm do remoto público (`v2.7.0-rc.1`, `5d8c420`). O M0 está só na máquina do autor, e as contagens têm de se repetir sobre `baseline/modular-1`.
- O fecho de dependências do `ReleaseDecision` (`Vulnerability`, `RiskBreakdown`, ...) e, por isso, quantos tipos sobem com o `GateReport`.
- Se o G1 do M0 já inclui um caso `assess --gate`.
- Se o `cmd/assets` pertence ao assess, e se o `cmd/evaluate` ou o `main.go` usam o `pkg/report` para mais do que `FormatList` e `IsSupportedFormat`.
- O dono do `ingestion.LoadMany` chamado em `orchestrator/gate.go:199` (validação de controlos no caminho do gate).
- Se as cinco práticas do GDPR.35 aparecem discriminadas no `Finding` ou no relatório.
- Os campos de dependências externas dos pacotes movidos (por exemplo `yaml.v3` no catálogo).
