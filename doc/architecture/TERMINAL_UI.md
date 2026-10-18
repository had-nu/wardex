# Wardex Terminal UI

## Objetivo

A interface humana do Wardex foi desenhada a partir de uma referência visual de dashboard para terminal. A referência forneceu apenas a hierarquia visual; a marca, os dados e os textos pertencem ao Wardex.

## Princípios

- Mostrar primeiro o contexto da execução.
- Separar estado geral, progresso e resultados.
- Usar cor apenas para reforçar significado.
- Nunca depender exclusivamente de cor para indicar estado.
- Manter JSON, CSV e pipes sem decoração.
- Mascarar segredos em qualquer modo de apresentação.
- Adaptar a saída a terminais estreitos e sem Unicode.
- Não imprimir marca d’água ou tentar reproduzir uma imagem de fundo no terminal.

## Identidade visual

A marca, a paleta e as variantes documentais estão definidas em [BRANDING.md](BRANDING.md). A UI do terminal usa o roxo como acento de marca, ciano para estrutura e cores semânticas para estado; nenhum desses tokens altera a saída machine-oriented.

## Hierarquia visual

```text
Header
Session card
Phase list
Finding/gap cards
Executive summary
```

## Mapeamento de dados

| Elemento visual | Wardex |
|---|---|
| Session | `EvaluationOptions` / `GateOptions` |
| Phase | evento do pipeline/orchestrator |
| Finding/gap | `model.Finding` |
| Score | `FinalScore` |
| Confidence | confiança das mappings em `CoveredBy` |
| Summary | `model.ExecutiveSummary` |
| Gate decision | `model.GateReport` |

## Comportamento por destino

| Destino | Comportamento |
|---|---|
| TTY | Cards, bordas, cores e status semânticos |
| Pipe/arquivo | Saída estruturada sem ANSI ou banner |
| `NO_COLOR` | Labels e símbolos sem cor |
| `TERM=dumb` | Fallback ASCII, sem dependência de Unicode |
| CI | Relatórios estruturados e logs sem decoração |

## Primeiros componentes

A base em `pkg/ui` é responsável por:

- detectar capacidade do terminal e o perfil CI;
- controlar largura e fallback ASCII/Unicode;
- centralizar cores semânticas;
- sanitizar valores destinados ao terminal;
- activar progresso/dashboard apenas quando stdout e stderr são TTY e o formato é humano;
- renderizar header, rules, tabelas e linhas key/value;
- manter o renderer separado do domínio.

O pipeline deve enviar eventos ao renderer; ele não deve imprimir ANSI diretamente. `RunGate` publica também um `GateOutcome` final em todos os retornos, incluindo falhas de configuração, evidência e Early Exit, para que o comando possa renderizar o mesmo dashboard sem duplicar a tabela. A cobertura funcional alcança `wardex`, `wardex evaluate`, `wardex assess`, `wardex aggregate`, `wardex art14`, `wardex simulate`, `keygen`, `config`, `provenance`, `chain`, `hmac`, `audit`, `enrich`, `convert`, `assets`, `auth`, `contract`, `policy`, `state`, `gate`, `accept` e `trust`.

Permanecem deliberadamente machine-oriented, sem dashboard:

- `wardex completion` e `wardex help`;
- `wardex audit export`;
- `wardex config hash`;
- modos JSON/CSV, pipes, ficheiros e outputs de attestation.

Estes caminhos não são lacunas de migração: são contratos de interoperabilidade. A cobertura funcional está concluída; a matriz determinística e a smoke test PTY manual foram executadas como gate final de encerramento.

## Golden tests

Os snapshots visuais determinísticos ficam nos diretórios `testdata` dos pacotes com UI. Para verificar o contrato sem reescrever ficheiros:

```bash
go test ./... -run 'Golden'
```

Após uma alteração visual aprovada, os snapshots podem ser atualizados explicitamente com:

```bash
UPDATE_GOLDEN=1 go test ./... -run 'Golden'
```

O golden suite usa perfis ASCII sem ANSI para tornar as diferenças visíveis e evitar dependência de terminal, locale ou cor.

A matriz de perfis, pipes, logger e sanitização é validada com:

```bash
go test ./pkg/ui ./cmd/assets -run 'Matrix|PipeDestinations|Golden|Logger|Sanitize'
```

Cobre larguras estreitas, ANSI/truecolor, Unicode/ASCII, `NO_COLOR`, `TERM=dumb`, CI, logs textuais, control characters e outputs table/JSON/CSV sem decoração em destinos não interativos.

## Definição de conclusão

A migração pode ser marcada como concluída quando:

- todos os comandos humanos respeitam a separação stdout/stderr;
- paths machine-oriented não recebem dashboard, banner ou ANSI;
- `NO_COLOR`, `TERM=dumb`, CI e ASCII narrow estão testados;
- redirects de output são injectáveis e cobertos por testes;
- prompts interactivos falham de forma explícita em stdin/stdout/stderr não interactivos;
- a smoke test PTY manual passa em ANSI e ASCII.

A validação PTY manual é executada com `script -qec` sobre um comando real, complementada pela matriz determinística de profiles.
