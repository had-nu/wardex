> **Superseded** — this Portuguese working draft is kept for reference only. The canonical spec is [SPEC-M0-baseline.md](SPEC-M0-baseline.md).

# SPEC — Módulo 0: rede de segurança e higiene do repositório

Wardex · rascunho 0.2 · decisões mandatórias · 19 de outubro de 2026 · base: `main` @ `a75500b` (24 commits depois de v2.6.1)

## 1. Propósito

O módulo 0 não entrega funcionalidade. Entrega os meios para verificar que a modularização (módulos 1 a 5) não altera o comportamento do Wardex e que as fronteiras entre módulos se mantêm. Sem ele, «igualmente consolidado» é uma intenção e não uma propriedade verificável.

Produz seis coisas:

1. testes golden de caracterização dos fluxos integrados;
2. uma guarda de fronteiras com baseline;
3. pisos de qualidade que só sobem;
4. a higiene do repositório que não depende de nenhum módulo;
5. as ADRs e os templates que os módulos seguintes vão usar;
6. a normalização das specs: mesma estrutura e mesma nomenclatura em todas, verificadas por ferramenta.

## 2. Âmbito

**Dentro:** ferramentas de verificação, baselines, ADRs, templates, a normalização das specs, movimentação de ficheiros que não são código de produção e têm verificação automática, e o pré-requisito P0 (secção 4).

**Fora:** mover código de produção entre pacotes, alterar comportamento (exceto P0.2), a funcionalidade AIPD, e tudo o que pertença a um módulo (simulador, `frameworks/`, `templates/`, `spec/cddl`, `config/`). Esses itens estão listados em 5.4-B e acompanham o módulo dono.

## 3. Decisões herdadas (fechadas)

As decisões D1 a D12 são mandatórias. Prevalecem sobre qualquer análise ou plano anterior que as contradiga, incluindo a revisão de 19 de outubro com as notas L1 a L19. Os pontos dessa revisão que não colidem com elas (por exemplo a forma do `Diagnostic`, a composição de `convert` com `attest` e a do selo de versão) entram como material de partida das specs dos módulos donos, não como decisão.

| # | Decisão (mandatória) |
| --- | --- |
| D1 | Ordem: 0 → contracts → assess → regulatory → gate → integrity, com o PR mecânico do caminho `/v3` (D7) entre o M0 e o M1. O `regulatory` antecede o `gate` porque `accept/cli` importa `art14`. `adapters` e `facade` crescem com cada módulo, não são fases finais. |
| D2 | Um só `go.mod`. Cada módulo em `pkg/<modulo>/` (API pública) com a implementação em `pkg/<modulo>/internal/`. `contracts` são tipos puros, sem I/O, e não importam nada; `kit` são primitivas e só importam `contracts`. Regra dos dois consumidores: só sobe para `contracts` o que pelo menos dois módulos usam. O `config` divide-se em `pkg/contracts/config` (tipos, defaults, perfis, migração, validação) e `pkg/kit/configio` (`Load`, `ApplyProfile`). Primitivas previstas: `kit/reportio` e `kit/canonicalhash`, confirmadas nas specs do M2 e do M5. |
| D3 | JSON: `schema_version: 2` em snake\_case, opt-in por flag (nome proposto `--json-version`, valores `v1` e `v2`, fixado na ADR-003). O v1 (PascalCase) é o default até ao v3.0.0. O M0 congela o v1; o M1 acrescenta o v2 e os golden congelam os dois; a troca do default faz-se no M7, com `Golden-Change`. |
| D4 | Erros: modelo único tipo de erro → exit code em `contracts`; `Diagnostic` no resultado em vez de `ui.Warnf`. A forma exata do `Diagnostic` e a sua presença no JSON v2 fecham-se na spec do M1. |
| D5 | Reestruturar e acrescentar funcionalidade não se misturam. O golden só muda com um trailer `Golden-Change:` aprovado. |
| D6 | Estrutura e nomenclatura de specs iguais para todos os módulos (secção 5.6). Definição de pronto igual para todos (secção 10). |
| D7 | Caminho do módulo Go: de `github.com/had-nu/wardex/v2` para `/v3`, num PR mecânico próprio entre o M0 e o M1 (ADR-006), com verificação de README, Dockerfile, `action.yml` e `examples/sdk`. Sem isto não existe um tag v3.0.0 instalável. Não se mistura com o M1. |
| D8 | `v2.7.0-rc.1` é pré-lançamento e serve de baseline, com C1 (mensagem do `policy`), B1 (`cra.support_period` e testes), P0.2 e CHANGELOG. O B1 é funcionalidade e entra antes do baseline. O conteúdo do branch `release/2.7.0` vem da revisão de 19 de outubro e confirma-se antes do corte. |
| D9 | O AIPD e a unificação do `internal/policy` com o `pkg/ingestion` ficam depois da modularização. O M2 só relocaliza o `internal/policy` para `pkg/assess/internal/policy` e expõe o serviço na facade. O AIPD é um pacote novo e aditivo e pode correr em paralelo depois do M2. |
| D10 | Cada módulo funde em `main` quando o seu critério de aceitação fecha. `main` fica sempre instalável e o v3.0.0 só sai no fim do M7. Não há branches empilhados. |
| D11 | Plano de referência (prazo): garantidos o M0 e o M1; o M2 só entra se o G1 se mantiver em 3 casos por fluxo. O prazo de duas semanas não foi validado. Estimativas da revisão de 19 de outubro, não validadas: M0 5 a 7 dias, M1 3 a 4, M2 4 a 5. |
| D12 | Precedência: esta spec e as decisões D1 a D12 prevalecem sobre qualquer análise anterior que as contradiga. |

## 4. Pré-requisito P0: baseline instalável

Contexto: o binário v2.6.1 não tem os catálogos `gdpr` e `cra`; a `main` tem. O `CHANGELOG [Unreleased]` está vazio apesar dos 24 commits, um dos quais remove o SOC 2 (mudança incompatível). O P0.1 está confirmado por execução (revisão de 19 de outubro): um controlo implementado, maturidade 4, com evidência e `domains: [governance]`, avaliado contra o GDPR, deixa o GDPR.35 em Partial e nunca chega a Covered. A causa está em `pkg/correlator/matcher.go`: `matchDomains` compara com `annexA.Domains`; só o `annex_a.yaml` declara `domains:` (93 ocorrências), os outros seis catálogos têm zero, e o `catalog.Load` não deriva `Domains` de `Domain`.

- **P0.1** Concluído: defeito confirmado (parágrafo anterior).
- **P0.2** Corrigir num PR próprio (derivar `Domains` a partir de `domain` no loader, ou mapeamento explícito `maps_to`). O PR inclui teste de comportamento do GDPR e o antes/depois dos outros frameworks sem `domains` (NIS2, DORA, EU AI Act, CRA), porque os resultados destes também mudam.
- **P0.3** Escrever o `CHANGELOG`, marcar a remoção do SOC 2 como incompatível e cortar `v2.7.0-rc.1` como pré-lançamento (D8), com C1, B1 e P0.2. Esse binário é o baseline dos golden e dá ao trabalho do DigiToys um binário com GDPR.

O P0.2 é obrigatório, e o baseline só se corta depois dele.

## 5. Componentes

### 5.1 Harness golden

**Método.** Caixa-preta. `TestMain` compila o binário uma vez com as flags do release (`-trimpath`). Cada caso copia `in/` para um diretório temporário, executa o binário e captura stdout, stderr, exit code e os ficheiros declarados. Só usa a linha de comandos, por isso sobrevive à movimentação de pacotes. Corre com `go test -tags golden ./test/golden/...`, fora do `go test ./...` normal.

```
test/golden/
  harness_test.go     # runner (build tag golden)
  normalize.go        # regras de normalização
  cases/<fluxo>/<caso>/
    case.yaml
    in/               # entradas (inclui chaves de teste, não secretas)
    want/stdout.txt  want/stderr.txt  want/exit  want/files/
```

```yaml
# case.yaml
id: assess-iso27001-ambas-camadas
flow: G1
args: [assess, documented.yaml, implemented.yaml, --framework, iso27001, --output, json]
outputs: []                      # ficheiros produzidos a comparar
normalize: [timestamps, tmpdir, version]
known_defect: ''                 # id da issue, se o resultado atual é um defeito conhecido
```

**Normalização.** Timestamps RFC 3339 → `<TS>`; caminho do diretório temporário → `<TMP>`; versão → `<VERSION>`; fins de linha LF; JSON recodificado com indentação fixa antes de comparar. Qualquer outra instabilidade (ordem de mapas, aleatoriedade, rede) é defeito do caso e não se resolve alargando a normalização.

**Determinismo.** Cada caso corre duas vezes; se os resultados normalizados diferirem, o caso é rejeitado.

**Isolamento.** Sem rede (EPSS por ficheiro local, via `epssPath`). Sem geração de chaves: as chaves Ed25519 de teste vão nas entradas, marcadas como não secretas; `keygen` só é testado quanto a formato e permissões. `provenance` só com os drivers noop e embedded (o gRPC está atrás de build tag e fica fora).

**Política de atualização.** `make golden-update` reescreve `want/`. A CI falha se `test/golden/**/want/**` mudar num PR sem o trailer `Golden-Change: <ADR ou issue>` num commit. Um caso com `known_defect` só muda no PR que corrige o defeito, com o trailer.

**Fluxos obrigatórios** (mínimo de 3 casos por fluxo: caminho feliz, falha esperada com exit code, entrada inválida):

| Fluxo | Comandos | Conteúdo congelado |
| --- | --- | --- |
| G1 | `assess` | 7 frameworks (iso27001, nis2, dora, eu\_ai\_act, nist\_csf, gdpr, cra) × {só documented, só implemented, ambas, com ativos}; JSON em todos, Markdown/CSV/HTML em iso27001 e gdpr |
| G2 | `assess` + snapshot | guardar e comparar → delta |
| G3 | `evaluate` | vulnerabilidades → decisão e exit code, com aceitações, EPSS local e exploração ativa |
| G4 | `convert` | Grype e KEV → YAML; leitura de CycloneDX, SPDX e OpenVEX |
| G5 | `aggregate` | vários resultados → decisão única |
| G6 | `art14` | ciclo de vida completo dos artefactos |
| G7 | `trust`, `auth`, `configseal` | com chaves de fixture |
| G8 | `chain`, `state`, `gate`, `audit`, `hmac`, `contract` | incluindo o selo de versão (exit 13) |
| G9 | `provenance` | drivers noop e embedded |
| G10 | `policy` | ficheiros de `frameworks/` |

**Matriz do G1.** A matriz define-se em dados, em `cases/G1/matrix.yaml`, com os eixos `framework`, `camadas`, `ativos` e `formato`. O harness expande-a em ids (`G1-<framework>-<camadas>-<formato>`) e guarda cada `want/` em `cases/G1/want/<id>/`. O mínimo de 3 casos aplica-se aos passos P2 e P3; a matriz completa é critério para fechar o M0. Se a normalização não bastar para o HTML, comparam-se invariantes (cabeçalhos e contagens).

O `simulate` fica só com teste de arranque e fim, sem golden de conteúdo. As flags de cada comando levantam-se com `--help` na implementação.

### 5.2 Guarda de fronteiras

Ferramenta `tools/check-boundaries`, na mesma convenção das existentes (`go run`, sem dependências externas), executada no job Test da CI.

```yaml
# doc/architecture/modules.yaml
version: 1
modules:
  contracts:  { packages: [pkg/contracts],  may_import: [] }
  kit:        { packages: [pkg/kit],        may_import: [contracts] }
  assess:     { packages: [pkg/assess],     may_import: [contracts, kit] }
  regulatory: { packages: [pkg/regulatory], may_import: [contracts, kit] }
  gate:       { packages: [pkg/gate],       may_import: [contracts, kit] }
  integrity:  { packages: [pkg/integrity],  may_import: [contracts, kit] }
  facade:     { packages: [pkg/sdk],        may_import: [assess, regulatory, gate, integrity, contracts, kit] }
  adapters:   { packages: [cmd, pkg/ui, .], may_import: [facade, contracts, kit] }
  tests:      { packages: [test, examples], may_import: [facade, contracts, kit] }
  tools:      { packages: [tools],          may_import: [] }
legacy:   # gerado por `check-boundaries -init` a partir do grafo atual
  - { package: pkg/analyzer, target: assess, allow: [pkg/ui] }
  - { package: pkg/accept/cli, target: gate, allow: [pkg/art14, pkg/ui] }
```

**Regras**

- R1 `contracts` não importa pacotes do repositório; `kit` só importa `contracts`.
- R2 Um módulo só importa `contracts`, `kit` e os seus próprios pacotes.
- R3 Só a `facade` importa mais do que um módulo.
- R4 Só os `adapters` importam `pkg/ui`.
- R5 Os `adapters` só usam a API pública dos módulos.
- R6 Pacote não classificado (nem em `modules` nem em `legacy`) é erro.
- R7 Código de produção fora de `pkg/` (hoje `config/`, `internal/cpl`, `internal/policy`, `internal/notification`) tem de ter destino no manifesto.
- R8 `tools/` é folha: não importa pacotes do repositório.

**Classificação e execução.** `tools/` é folha; `test/` e `examples/` classificam-se como `tests` e só consomem a facade, o `contracts` e o `kit`. O checker corre também com `-tags grpc`, para apanhar `provenance/grpc.go`, e ignora os imports de ficheiros `_test.go`.

**Linha de base.** A secção `legacy` lista as violações atuais (por exemplo `analyzer → ui`, `accept/cli → art14`, os 22 imports do `orchestrator`). A ferramenta falha se surgir uma violação nova e também se uma violação da baseline desaparecer sem ser removida do ficheiro, para a baseline não ficar desatualizada. Depois de cada módulo migrar, o `internal/` impõe o encapsulamento pelo compilador e o manifesto continua a impor os contratos entre módulos.

### 5.3 Pisos de qualidade

Ferramenta `tools/check-ratchet`, baselines em `tools/baselines/`.

- **Cobertura por pacote.** Lê o `-coverprofile` e compara com `coverage.json`. Piso inicial = cobertura atual arredondada para baixo. O piso só sobe (`make ratchet-update` recusa descidas). O limiar global de 40 % mantém-se. Os pacotes sem testes (`pkg/model`, `pkg/gate`, `pkg/accept/rules`, `pkg/utils`) entram com piso 0 e a marca `untested`.
- **Lint.** Remover as três exclusões de `errcheck` por padrão `_ =`, que neutralizam o `check-blank: true`, e a exclusão para `research/`, que aponta para um diretório inexistente. Acrescentar `funlen` (proposta: 100 linhas, 60 instruções) e `forbidigo` (`os.Exit`, `fmt.Print*`) com baseline. Hoje há cerca de 64 `_ =` em `pkg/` e 18 funções acima de 100 linhas.
- **Mecanismo de baseline do lint.** `issues.new-from-rev` fixado no tag `baseline/modular-0`, ou o equivalente da v2.15 (sintaxe a confirmar). Alternativa: ficheiro de baseline gerado por ferramenta.
- **`#nosec`.** `tools/check-nosec` falha num `#nosec` sem código de regra e sem justificação. Baseline: as 20 ocorrências atuais sem justificação (de 40).
- **Regra por módulo.** Código movido ≥ 60 % de cobertura; código novo ≥ 80 %. Cada módulo remove da baseline as entradas dos seus pacotes.

### 5.4 Higiene do repositório

**A. Faz-se no módulo 0**

- `doc/INDEX.md` passa a incluir o mapa do repositório: `doc/` documentação, `docs/` site publicado (GitHub Pages, não se renomeia porque o Pages serve desta pasta), `spec/cddl` esquemas CDDL, `test/` testes.
- `chain-seal-v2.4.0.json` e `chain-seal-v2.4.1.json` → `doc/releases/seals/`. Atualizar as duas referências (`doc/releases/v2.4.0-notes.md` e `CHANGELOG.md`). Verificação: `check-doclinks`, mais confirmação de que nenhuma CI, Dockerfile ou `action.yml` os lê pela raiz.
- Remover a exclusão de lint para `research/`.
- Targets novos no `Makefile` (secção 7).
- `lazygo.yml` só é referenciado pelo `.gitignore`. Confirmar a finalidade com o autor. Se for configuração pessoal, deixa de ser versionado.

**B. Acompanha o módulo dono (não se mexe agora)**

| Item | Destino |
| --- | --- |
| `config/` (pacote Go fora de `pkg/`) | contracts: divide-se em `contracts/config` e `kit/configio` (D2) |
| `pkg/catalog/*.yaml` e `frameworks/*.yml` | assess. Segundo a decisão registada na sessão de implementação, o catálogo são definições normativas e `frameworks/` são asserções do operador: camadas distintas, não duplicados. Faltam os esqueletos de gdpr, cra, nist\_csf e annex\_a. Renomear `frameworks/` para `policies/` é hipótese a decidir na spec do M2. A confirmar antes de assumir. |
| `test/wardex-risk-simulator.jsx` e `test/embed.go` (embebido por `cmd/simulate`) | gate: o conteúdo passa para o pacote do gate e é exposto pela API pública dele, via facade, porque o `internal/` do gate não é acessível aos adapters. O pacote `test` da raiz desaparece e `test/` fica só com testes. |
| `data/` (`calibration.json`, `dataset_2025-03-01.json`), `testdata/` na raiz, `test/testdata/` | inventariar quem lê cada um; convenção Go: `testdata/` junto do pacote |
| `templates/*.tmpl`, `signatures/version1`, `spec/cddl` | integrity |
| `dashboard_view.go` e testes no `package main` da raiz | adapters, com o primeiro comando migrado |
| `INPUT_GUIDE.md`, `RELEASES.md` na raiz | avaliar mover para `doc/` depois de verificar referências no código e no README |

### 5.5 ADRs e templates

Em `doc/architecture/adr/`, uma página cada (contexto, decisão, consequências, alternativas rejeitadas):

- ADR-001 ordem e módulos (alternativa rejeitada: ordem por uso em execução);
- ADR-002 layout e encapsulamento (alternativa rejeitada: `go.work` multi-módulo);
- ADR-003 política de JSON v2 e janela de deprecação do v1;
- ADR-004 erros e `Diagnostic`;
- ADR-005 definição de pronto, pisos e política de golden (alternativa rejeitada: `contracts` único sem `kit`);
- ADR-006 caminho do módulo Go para `/v3` (alternativas rejeitadas: subir dentro do M1, subir só no M7, não subir).

Template de spec em `doc/specs/TEMPLATE_modulo.md`, gerado a partir da estrutura canónica da secção 5.6 e validado pelo `check-specs`.

### 5.6 Normalização das specs

Todas as specs (M0 a M7 e as transversais) seguem a mesma estrutura e a mesma nomenclatura, e isso verifica-se por ferramenta e não por revisão.

**Estrutura canónica.** Doze secções, na mesma ordem e com os mesmos títulos em todas as specs. Uma secção sem conteúdo aplicável fica com «N/A» e a razão numa linha; nunca se omite.

| # | Título fixo | Conteúdo |
| --- | --- | --- |
| 1 | Propósito | o que o módulo entrega e porquê |
| 2 | Âmbito | dentro e fora |
| 3 | Decisões herdadas | tabela de decisões: as globais por referência, as do módulo como `M<n>-D<k>` |
| 4 | Pré-requisitos | o que tem de existir antes (módulos, PRs, baseline) |
| 5 | Componentes | abre com a ficha do módulo; depois um subcapítulo por componente (`5.1`, `5.2`) |
| 6 | Modelo de erros | tipos de erro, exit codes, diagnósticos |
| 7 | Uso isolado | como usar o módulo sozinho, por comando ou exemplo de código |
| 8 | Plano de testes | golden, unitários, fuzz, fronteiras, sensibilidade |
| 9 | Plano de migração | passos `M<n>-P<k>` com critério de aceitação |
| 10 | Definição de pronto | lista verificável |
| 11 | Riscos | risco e mitigação |
| 12 | Não verificado | o que não foi confirmado e como se confirma |

**Ficha do módulo.** Tabela no início da secção 5, com as mesmas oito linhas em todas as specs: Entradas, Saídas, API pública, Dependências permitidas, Pacotes absorvidos, Comandos absorvidos, Branch, Estimativa. No M0: sem API pública (são ferramentas e testes), só stdlib como dependência, sem pacotes nem comandos absorvidos, branch `mod/0-baseline`.

**Nomenclatura.**

| Elemento | Formato | Exemplo |
| --- | --- | --- |
| Ficheiro de spec | `doc/specs/SPEC-M<n>-<id>.md`; transversais `SPEC-X-<tema>.md` | `SPEC-M2-assess.md`, `SPEC-X-help.md` |
| `<id>` | id do módulo no manifesto, em minúsculas; `baseline` para o M0 | `contracts`, `gate` |
| Título | `SPEC-M<n> — <Nome>` | `SPEC-M0 — Baseline: rede de segurança e higiene do repositório` |
| Byline | `Wardex · <estado> <versão> · <data> · base: <ref>`; estados `rascunho`, `aceite`, `implementado`, `legado` | `Wardex · rascunho 0.2 · 19 de outubro de 2026 · base: main @ a75500b` |
| Decisão | `D<n>` global; `M<n>-D<k>` do módulo | `D7`, `M1-D2` |
| Regra, fluxo, componente | `R<n>`, `G<n>`, `<secção>.<n>` | `R4`, `G3`, `5.2` |
| Passo | `M<n>-P<k>` | `M0-P5` |
| Referência cruzada | `<spec>#<id>` | `M0#R4` |
| ADR | `doc/architecture/adr/ADR-<nnn>-<slug>.md` | `ADR-006-caminho-v3.md` |
| Branch e tag | `mod/<n>-<id>` e `baseline/modular-<n>` | `mod/1-contracts` |

**Glossário.** Um termo por conceito, em `doc/specs/glossario.yaml` (a fonte que a ferramenta lê).

| Termo canónico | Não usar |
| --- | --- |
| baseline | linha de base |
| teste golden | teste de caracterização (só na primeira definição) |
| piso (de cobertura) | ratchet, exceto no nome `check-ratchet` |
| guarda de fronteiras | boundary check |
| módulo (agrega pacotes) | pacote, quando se quer dizer módulo |
| definição de pronto (do módulo) | critérios de fecho; «critério de aceitação» é só dos passos |
| ficheiro | arquivo |

**Ferramenta.** `tools/check-specs`, na convenção das outras (`go run`, sem dependências externas), corre na CI com o `check-doclinks`. Verifica: nome do ficheiro e título; byline; as 12 secções, por ordem e com o título exato; a ficha do módulo com as 8 linhas; IDs únicos por spec e referências cruzadas que resolvem; sinónimos proibidos do glossário fora de blocos de código; e que o próprio template cumpre tudo isto. Usa os códigos de saída da secção 6. As specs `legado` ficam isentas das regras de conteúdo (secções, ficha, IDs, glossário), mas não do nome e da byline.

**Âmbito e inventário.** Specs M0 a M7, specs transversais (por exemplo AIPD e ajuda/manual, quando existirem) e ADRs (formato fixo: contexto, decisão, consequências, alternativas rejeitadas). As specs que já existem em `doc/specs/` inventariam-se e classificam-se, uma a uma e com o autor, em «conformar» ou «legado» (congelada, sem reescrever o histórico).

**Conversão desta spec.** É o primeiro caso do `check-specs` (passo P8): título e byline no formato canónico, secção 4 renomeada «Pré-requisitos» com o P0 lá dentro, ficha do módulo no início da secção 5, passos renomeados `M0-P<k>`, glossário aplicado, e passagem para `doc/specs/SPEC-M0-baseline.md`.

## 6. Modelo de erros das ferramentas

Códigos de saída comuns: `0` sem violações; `1` violação nova; `2` erro de configuração, manifesto ou baseline; `3` item não classificado ou caso não determinístico. As mensagens seguem o formato `ficheiro:linha REGRA descrição`, com `-json` opcional.

## 7. Uso isolado

```
make golden            # go test -tags golden ./test/golden/...
make golden-update     # reescreve want/ (exige trailer Golden-Change)
make boundaries        # go run ./tools/check-boundaries
make ratchet           # cobertura por pacote, nosec e lint contra as baselines
make ratchet-update    # só aceita subidas
make specs             # go run ./tools/check-specs
make baseline-check    # tudo o anterior, igual ao job de CI
```

## 8. Plano de testes do próprio módulo

- **Normalizador:** tabela de entradas (timestamps em vários formatos, caminhos, versão) → saída esperada.
- **Guarda de fronteiras:** grafos sintéticos, uma violação por regra R1 a R8, e uma baseline que fica desatualizada.
- **Pisos:** subida aceite, descida rejeitada, pacote novo sem piso.
- **Harness:** duplo run em todos os casos.
- **Normalização das specs:** specs sintéticas, uma violação por regra do `check-specs` (nome, byline, secção em falta ou fora de ordem, ficha incompleta, ID duplicado, referência cruzada partida, sinónimo proibido); o template cumpre as mesmas regras.
- **Sensibilidade (manual, antes de fechar o módulo):** aplicar cinco mutantes à `main`; o golden tem de falhar em pelo menos quatro. (m1) o limiar fixo de maturidade em `EvaluateCoverage`; (m2) um exit code do gate; (m3) remover `layer_delta` do JSON do `assess`; (m4) inverter a ordem do roadmap; (m5) a confiança devolvida por `matchDomains`.

## 9. Plano de migração

| Passo | Trabalho | Critério de aceitação |
| --- | --- | --- |
| P0 | Secção 4 (P0.1 concluído; P0.2 e P0.3 por fazer) | `v2.7.0-rc.1` publicado como pré-lançamento, com C1, B1, P0.2 e CHANGELOG |
| P1 | Medir a cobertura real por pacote na CI | tabela por pacote publicada como artefacto |
| P2 | Harness + normalizador + 3 casos de G1 | duplo run estável; 3 casos verdes na CI |
| P3 | Casos G1 a G10, com a matriz do G1 gerada de dados | ≥ 3 casos por fluxo verdes na rc.1; matriz completa verde antes de fechar o M0 |
| P4 | Guarda de fronteiras com `-init`, incluindo `tools`, `test` e `examples` no manifesto | verde na `main` com e sem `-tags grpc`; uma violação nova injetada falha |
| P5 | Baselines de cobertura, lint e `#nosec`; remover exclusões | CI verde; uma regressão injetada falha |
| P6 | Higiene A | `check-doclinks` verde; nada lê os ficheiros movidos pela raiz |
| P7 | 6 ADRs e template de spec | 6 ADRs aceites; template criado segundo a secção 5.6 |
| P8 | Normalização das specs (5.6): glossário, `check-specs`, inventário de `doc/specs/`, conversão desta spec | `check-specs` verde na CI; todas as specs conformes ou marcadas `legado`; o template valida-se a si próprio |
| P9 | Sensibilidade e tag `baseline/modular-0` | ≥ 4 de 5 mutantes detetados; tag criada |

Dependências: P1 antes de P5; P2 antes de P3; P7 antes de P8; P4, P6 e P7 são independentes entre si; P9 é o último. O PR do caminho `/v3` (D7) vem depois do M0 e antes do M1. Estimativa do P8 (minha, a validar): 1 a 2 dias.

## 10. Definição de pronto

- Os 10 fluxos têm ≥ 3 casos, estáveis em duplo run e verdes na rc.1, e a matriz do G1 está completa.
- A guarda de fronteiras corre na CI (com e sem `-tags grpc`), com baseline gerada, e uma regressão injetada falha.
- As baselines de cobertura, lint e `#nosec` estão na CI, e uma regressão injetada falha.
- As exclusões que anulavam o `errcheck` e a de `research/` foram removidas.
- A higiene A está concluída e o `check-doclinks` passa.
- As 6 ADRs, o template de spec e o glossário estão no repositório.
- O `check-specs` corre na CI; todas as specs estão conformes ou marcadas `legado`, e esta spec foi convertida.
- A sensibilidade é ≥ 4 de 5.
- Nenhum ficheiro de produção mudou desde a `v2.7.0-rc.1`, comprovado com `git diff --stat v2.7.0-rc.1..HEAD -- pkg cmd`.

## 11. Riscos

- **Golden instável** (tempo, ordem, rede). Mitigação: normalização estrita, duplo run, sem rede, chaves de fixture.
- **Golden frágil em HTML.** Mitigação: comparar após normalização; se a fragilidade persistir, reduzir a invariantes (cabeçalhos, contagens).
- **Baseline que congela defeitos.** Mitigação: `known_defect` e o trailer `Golden-Change`.
- **Baseline de fronteiras desatualizada.** Mitigação: a ferramenta falha quando uma violação desaparece sem ser retirada do ficheiro.
- **Mover ficheiros quebra links ou CI.** Mitigação: `check-doclinks` e pesquisa de referências antes de mover.
- **Ferramentas a mais para um só mantenedor.** Mitigação: quatro binários pequenos em `tools/`, na convenção das existentes, sem dependências externas.
- **Normalização que vira burocracia.** Mitigação: o `check-specs` valida estrutura, IDs e vocabulário, nunca o conteúdo; as specs `legado` ficam isentas.
- **Caminho `/v3` que parte imports, README, Dockerfile ou `action.yml`.** Mitigação: PR mecânico próprio (D7), com os golden e a guarda de fronteiras como rede.
- **Toolchain.** A CI usa Go 1.27.2; documentar no `CONTRIBUTING.md`.

## 12. Não verificado (a levantar na implementação)

- Flags e formatos de saída de cada comando (`--help`).
- A cobertura real por pacote (nenhum teste foi executado nesta análise).
- A sintaxe de baseline do golangci-lint v2.15.
- A finalidade de `lazygo.yml`, `data/`, `signatures/version1`, e se `wardex-config.yaml` na raiz é usado pela CI, pelo Dockerfile ou pelo `action.yml`.
- Se os `chain-seal-*.json` são lidos por algum fluxo de verificação pela raiz.
- O conteúdo exato de C1 e B1 no branch `release/2.7.0`: vem da revisão de 19 de outubro e não foi visto por mim.
- A decisão sobre `pkg/catalog` (normativo) e `frameworks/` (asserções do operador): vem da sessão de implementação e não a verifiquei.
- O conteúdo atual de `doc/specs/` (não foi inventariado) e qual é a fonte das specs depois da conversão: o repositório ou o documento editável.
