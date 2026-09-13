# Manual de Onboarding — Wardex

> **WARDEX — Risk-based Release Gate for Threat-Informed Intelligence strategies**
> CLI e biblioteca Go que transforma decisões de segurança e conformidade em **evidência auditável e criptograficamente selada**.

Este manual é o ponto de partida para quem está a chegar ao projeto — seja para um primeiro contacto, onboarding de um júnior, ou para consulta rápida durante o desenvolvimento. O conteúdo foi derivado do grafo de conhecimento do projeto (`.ua/knowledge-graph.json`) e do código-fonte real.

---

## Índice

1. [O que é o Wardex](#1-o-que-é-o-wardex)
2. [Posicionamento e Regulamentação](#2-posicionamento-e-regulamentação)
3. [Estrutura do Repositório](#3-estrutura-do-repositório)
4. [Arquitetura em Camadas](#4-arquitetura-em-camadas)
5. [Como fazer build e executar](#5-como-fazer-build-e-executar)
6. [Conceitos-Chave](#6-conceitos-chave)
7. [Comandos CLI](#7-comandos-cli)
8. [Fluxo de Dados Principal](#8-fluxo-de-dados-principal)
9. [Testes](#9-testes)
10. [Guia para Juniors: por onde começar](#10-guia-para-juniors-por-onde-começar)
11. [Como adicionar um novo framework](#11-como-adicionar-um-novo-framework)
12. [Pitfalls e Dicas](#12-pitfalls-e-dicas)
13. [Convenções de Código](#13-convenções-de-código)

---

## 1. O que é o Wardex

O **Wardex** é uma **CLI e biblioteca Go** (`github.com/had-nu/wardex/v2`) que transforma decisões de segurança e conformidade em **evidência auditável**. Opera em dois modos independentes:

1. **Gap Analysis** — avalia o estado de conformidade de uma organização contra catálogos de controlos de regulamentos/frameworks (NIS2, DORA, CRA, EU AI Act, ISO 27001, SOC 2).
2. **Release Gate** — avalia uma lista de vulnerabilidades e produz uma decisão de risco (**ALLOW / WARN / BLOCK**) com base num *risk appetite* configurável.

Cada decisão, cada aceitação de risco e cada artefacto regulamentar é **selado criptograficamente** e registado num **audit log encadeado** à prova de adulteração.

**A filosofia central:** *"não confies em mim, verifica a evidência"*. O Wardex não se limita a reportar conformidade — gera uma trilha verificável que sobrevive a auditorias externas.

### Autoria e licenciamento

- **Autor:** André Gustavo Leão de Melo Ataíde (`had-nu`)
- **Licença:** dupla — **AGPL-3.0** (uso livre/open-source/CI) + **Comercial** (proprietário/SaaS). Ver `LICENSE` e `LicenseRef-Wardex-Commercial.txt`.
- **Taxa de cobertura:** ~50% (e a crescer — o projeto está ativamente a adicionar testes).

---

## 2. Posicionamento e Regulamentação

O Wardex é construído **de raiz para a regulamentação europeia**, e para o padrão de compliance emergente na UE:

| Regulamentação | Estado | Notas |
|---|---|---|
| **NIS2** | Suportado | Diretiva de segurança de redes/informação |
| **DORA** | Suportado | Regulamento de resiliência operacional digital (financeiro) |
| **CRA Art. 14** | Suportado (v2.0+) | **Notificação de exploração ativa** — correlação com catálogo CISA KEV, exit code distinto `12`, centro do release gate |
| **EU AI Act** | Suportado (v2.4.0+) | Regulamento IA (UE 2024/1689), 31 controlos catalogados |
| **ISO/IEC 27001:2022** | Suportado | Anexo A |
| **SOC 2** | Suportado | Trust Services Criteria |
| **NIST CSF 2.0** | Suportado | Estrutura de cibersegurança |

> [!IMPORTANT]
> O caminho **CRA Article 14** (exploração ativa) **não pode ser substituído por aceitações de risco**. É uma obrigação regulamentar com prazos próprios (3 deadlines), irrevogável via aceitação.

---

## 3. Estrutura do Repositório

```
wardex/
├── main.go                 # Raiz da CLI Cobra (regista os 18 subcomandos)
├── cmd/                    # Implementação dos 18 subcomandos CLI
│   ├── aggregate/  assess/  assets/  art14/  audit/  auth/
│   ├── chain/  configseal/  contract/  convert/  evaluate/
│   ├── hmac/  keygen/  policy/  provenance/  simulate/  state/  trust/
├── pkg/                    # Biblioteca pública (27 packages)
│   ├── accept/  analyzer/  art14/  atomicwrite/  attest/
│   ├── catalog/  cli/  correlator/  duration/  enrich/  epss/
│   ├── exitcodes/  gate/  ingestion/  model/  orchestrator/
│   ├── provenance/  releasegate/  report/  sboms/  scorer/  sdk/
│   ├── snapshot/  statestore/  trust/  ui/  utils/
├── internal/               # Packages internos (não importáveis externamente)
│   ├── cpl/                # Config Provenance Link (canonicalização/hash)
│   ├── notification/       # Notificações de divergência (Slack webhooks)
│   ├── policy/             # Carregamento de políticas
│   └── doc/                # Documentação interna / guias de migração
├── config/                 # Carregamento e validação de configuração
├── frameworks/             # Catálogos de controlos (dora, eu_ai_act, iso27001, nis2, soc2)
├── spec/cddl/              # Esquemas CDDL (RFC 8610) para serialização
├── data/                   # Datasets (calibração, dados históricos)
├── deploy/                 # Helm chart Kubernetes
├── templates/              # Templates Slack
├── doc/  docs/             # Documentação (arquitetura, operações, releases, governance)
├── test/  testdata/        # Testes e fixtures
└── tools/gen-sbom/         # Gerador de SBOM CycloneDX
```

**Nota sobre Go:** os diretórios `internal/` e `pkg/` têm significados distintos:
- `internal/` — packages **apenas importáveis dentro do módulo** (imposto pelo compilador).
- `pkg/` — **biblioteca pública**, importável por quem usa o Wardex como dependência.

---

## 4. Arquitetura em Camadas

O grafo de conhecimento identifica 10 camadas. As principais:

```
┌─────────────────────────────────────────────────────────────┐
│  CAMADA DE ENTRADA CLI (cmd/ + main.go) — 18 subcomandos    │
│  Cobra, flags core vs advanced, exit codes semânticos       │
├─────────────────────────────────────────────────────────────┤
│  BIBLIOTECA PÚBLICA (pkg/) — 27 packages                    │
│  analyze, catalog, gate, releasegate, art14, trust, ...     │
├─────────────────────────────────────────────────────────────┤
│  PACOTES INTERNOS (internal/) — cpl, policy, notification   │
├─────────────────────────────────────────────────────────────┤
│  CONFIGURAÇÃO E ESTADO — config/ + WexState + statestore    │
├─────────────────────────────────────────────────────────────┤
│  FRAMEWORKS DE CONFORMIDADE (frameworks/) — catálogos       │
├─────────────────────────────────────────────────────────────┤
│  DADOS E ESQUEMAS — spec/cddl, data/, testdata              │
├─────────────────────────────────────────────────────────────┤
│  INFRAESTRUTURA — Dockerfile, Helm, .github/, action.yml    │
└─────────────────────────────────────────────────────────────┘
```

### Papel de cada camada

1. **CLI Entry (`main.go` + `cmd/`)** — Reúne tudo via Cobra. `main.go:149-189` é o `init()` que regista os 18 subcomandos. É aqui que o programador vê o "mapa" do CLI inteiro.
2. **Biblioteca Pública (`pkg/`)** — O coração lógico. Cada subcomando `cmd/X` delega para o package `pkg/X`.
3. **Internos (`internal/`)** — `internal/cpl` é crítico: o **Config Provenance Link** que faz hash canónico da configuração. `internal/policy` carrega políticas.
4. **Config & Estado** — `config/` carrega `wardex-config.yaml`; `pkg/statestore` gere o estado persistente com hash-chaining BLAKE3; `pkg/trust` gere a trust store e config selada (WexState).
5. **Frameworks** — Os catálogos de controlos em YAML, lidos por `pkg/catalog`.
6. **Infra** — Build/release via Dockerfile, `.goreleaser.yaml`, Helm chart, GitHub Action.

---

## 5. Como fazer build e executar

### Pré-requisitos

- **Go 1.26+** (o projeto está a modernizar para 1.27)
- `golangci-lint` (para lint)
- `govulncheck` e `gosec` (para segurança)

### Comandos Make

```bash
make build       # go build -trimpath -o bin/wardex .
make test        # go test -v -race -coverprofile=coverage.out ./...
make lint        # golangci-lint run ./...
make security    # govulncheck ./... && gosec ./...
make clean       # rm -rf bin/ coverage.out
```

### Build manual / com features adicionais

```bash
# Build padrão
go build -o bin/wardex .

# Com driver de provenance gRPC (protegido por build tag para evitar panic no init)
go build -tags grpc -o bin/wardex .
```

> [!TIP]
> O driver gRPC de proveniência foi **isolado atrás da build tag `grpc`** para evitar panics na inicialização. Só o active se precisar de proveniência via servidor gRPC remoto.

### Primeiros passos

```bash
# Help
./bin/wardex --help
./bin/wardex verify-chain --help

# Gap analysis simples contra ISO 27001
./bin/wardex --framework iso27001 testdata/controls.yaml

# Release gate
./bin/wardex --gate testdata/*.yml --framework nis2
```

---

## 6. Conceitos-Chave

### 6.1 Audit Log Encadeado (feature principal)

É o coração do Wardex. Cada entrada é ligada criptograficamente à anterior:

```
Entrada 1 (genesis) --SHA-256--> Entrada 2 (decisão) --SHA-256--> Entrada 3 (aceitação)
        |                                  |                             |
        ▼                                  ▼                             ▼
   Config hash                      Config hash                    Config hash
       (CPL)                           (CPL)                         (CPL)
```

- Cada entrada inclui o **hash da entrada anterior** (hash encadeado).
- O **hash de configuração (CPL)** liga cada decisão à política em vigor.
- Alterações ao audit log ou à configuração são detetadas imediatamente.
- Exportável como **JSONL** para SIEM, Datadog, ou auditoria externa.

**Comandos:**
```bash
wardex audit verify-chain --audit-log wardex-gate-audit.log
wardex audit verify-link --audit-log wardex-gate-audit.log --config-archive ./configs/
```

### 6.2 CPL — Config Provenance Link

O `internal/cpl` produz o **hash canónico** da configuração. Na v2.3.0+ a canonicalização migrou para **CBOR Core Deterministic Encoding (RFC 8949 §4.2.3)** via `fxamacker/cbor/v2`, garantindo byte-identicidade entre plataformas. O CPL liga cada decisão do gate à política exacta que estava em vigor na altura.

### 6.3 Release Gate — Decisão por risco

O `pkg/releasegate` avalia vulnerabilidades (EA com scores CVSS, EPSS, contexto de ativos) contra o **risk appetite** configurado:

| Decisão | Significado | Exit code |
|---|---|---|
| **ALLOW** | Dentro do apetite de risco | 0 |
| **WARN** | Excedeu `WarnAbove` | 0 (mas reporta aviso) |
| **BLOCK** | Excedeu o apetite de risco | 10 |

O scoring combina **CVSS × EPSS × contexto** (`pkg/scorer`). A maturidade inferida ajuda a priorizar.

### 6.4 EPSS — Probability of Exploitation

O `pkg/epss` conecta-se à **API FIRST.org** para buscar a probabilidade de exploração real. Vulnerabilidades sem EPSS podem default para pior-caso (1.0). O `cmd enrich epss` busca e **assina criptograficamente** o enrichment (HMAC).

### 6.5 CRA Article 14 — Notificação de exploração ativa

O `pkg/art14` implementa o ciclo de vida completo do artefacto de notificação:
- Correlação com o **catálogo CISA KEV**.
- 3 **deadlines regulamentares** de notificação.
- Artefacto assinado com **HMAC-SHA256**.
- Registado no audit log encadeado.
- **Exit code distinto `12`** para exploração ativa.

**Não pode ser contornado por aceitações de risco.**

### 6.6 Proveniência e Trust (3CP + Ed25519)

- **`pkg/attest`** — atestação **Ed25519 + CBOR determinístico** para provenance de ferramentas (grype, sbom, kev).
- **`pkg/provenance`** — interface `Anchorer` que abstrai o backend **3CP** (Gleipnir embedded, gRPC, ou noop). `wardex provenance seal/attest`.
- **`pkg/trust`** — trust store: `keygen`, `trust init/add/revoke`, modos Ed25519 e **PKI**, config selada (WexState).

### 6.7 WexState — Configuração selada

A configuração selada (`pkg/statestore`, `cmd/configseal`) garante que a política não muda sem ser detetada. O estado persistente usa **hash-chaining BLAKE3**.

### 6.8 Exit Codes

`pkg/exitcodes` define códigos semânticos (códigos >= 10 para gate/compliance):

| Código | Significado |
|---|---|
| 0 | OK |
| 1 | Erro genérico |
| 3 | Falha de integridade |
| 4 | Store inconsistente |
| 5 | Expiração próxima |
| 10 | Release gate bloqueado |
| 11 | Falha de conformidade |
| 12 | **Exploração ativa (CRA Art. 14)** |

---

## 7. Comandos CLI

O CLI tem **18 subcomandos** registados em `main.go:168-188`. Cada um delega num package `pkg/` correspondente.

### Subcomandos principais

| Comando | Purpose | Package backend |
|---|---|---|
| `wardex assess` | Gap analysis completo: config → ingestão → catálogo → correlação → análise → relatório | `pkg/analyzer`, `pkg/catalog`, `pkg/correlator` |
| `wardex evaluate` | Avalia o **release gate** contra um ficheiro de vulnerabilidades | `pkg/releasegate`, `pkg/analyzer` |
| `wardex aggregate` | Agrega decisões ALLOW/BLOCK multi-framework a partir de múltiplos relatórios | `pkg/gate` |
| `wardex art14` | Ciclo de vida dos artefactos CRA Article 14 (assinados HMAC) | `pkg/art14` |
| `wardex audit` | Audita a cadeia (`verify-chain`, `verify-link`) e proveniência da config | `pkg/audit` |
| `wardex convert` | Converte outputs de terceiros (grype, sbom, kev) para o formato Wardex | `pkg/convert`, `pkg/sboms` |
| `wardex chain` | Gestão de **chain seals** | `pkg/chain` |
| `wardex trust` | Gestão da trust store (init/add/revoke/list/show/verify) | `pkg/trust` |
| `wardex keygen` | Gera keypair **Ed25519** | `pkg/trust` |
| `wardex configseal` | Sela criptograficamente uma config draft (verifica/`show` hash) | `internal/cpl` |
| `wardex policy` | Gestão de políticas (validate/list/add/check-expiry) | `internal/policy` |
| `wardex provenance` | Proveniência (submit/verify/status/seal/attest) via 3CP | `pkg/provenance`, `pkg/attest` |
| `wardex state` | Gestão do estado persistente (status/history/trend/verify) | `pkg/statestore` |
| `wardex auth` | Verificação de integridade do trust store + permissões RBAC | `pkg/trust` |
| `wardex hmac` | Assinaturas HMAC-SHA256 | `pkg/trust` |
| `wardex contract` | Integridade de ficheiros de contrato (SHA-256) | `cmd/contract` |
| `wardex assets` | Inventário ICT (asset management) | `pkg/analyzer` |
| `wardex simulate` | Gera um *Risk Simulator* HTML interativo (React) | `cmd/simulate` |
| `wardex enrich epss` | Busca probabilidades EPSS e assina o enrichment | `pkg/epss` |

### Flags principais do root

```bash
--config PATH       Caminho para wardex-config.yaml (default ./wardex-config.yaml)
--framework NAME    iso27001|soc2|nis2|dora|nist_csf|eu_ai_act
--gate FILE         Ficheiro de vulnerabilidades para o release gate
--gate-mode         any|aggregate
--output FORMAT     markdown|json|csv
--fail-above F      Exit code 1 se gap com final_score > F
--min-confidence     high|low
--profile NAME      Override de thresholds RBAC
--verbose
```

---

## 8. Fluxo de Dados Principal

### 8.1 Gap Analysis (`wardex assess` e root `wardex`)

```
config/ (wardex-config.yaml)
   │  config.Load()
   ▼
ingestion.LoadMany(args) ──► controlos implementados (YAML/JSON/CSV)
   ▼
catalog.Load(framework) ──► catálogo do framework (frameworks/)
   ▼
correlator.New(cat).Correlate(controls) ──► mappings (confiança high/low)
   ▼
analyzer.New(...).Analyze() ──► findings (coberto/parcial/gap) + scores
   ▼
model.GapReport + Roadmap (ordenado por FinalScore)
   ▼
report.Generate(rep, format, out) ──► markdown/json/csv
```

Este pipeline completo está em `main.go:199-412` (`runWardex`).

### 8.2 Release Gate (`wardex evaluate` / `--gate`)

```
gateFile (vulns YAML) ──► pathguard.SafePath (anti path-traversal)
   ▼
gate.FilterAccepted (remove aceites) + gate.ApplyEPSSEnrichment
   ▼
releasegate.Gate.Evaluate(vulns) ──► GateReport { ALLOW | WARN | BLOCK }
   ▼
Audit log encadeado + decisão reportada + exit code (10/11/12)
```

O release gate **só corre se** `cfg.ReleaseGate.Enabled && gateFile != ""` (`main.go:315`).

### 8.3 Nota sobre o fluxo de aceitação de risco

O `pkg/accept/cli` gere aceitações de risco residual, mas **o caminho CRA Art. 14 (exploração ativa) não é anulável por aceitação** — está protegido por verificação HMAC do artefacto (`runActiveExploit`).

---

## 9. Testes

O projeto tem cobertura em crescimento (~50%) com uma estratégia diversificada:

```bash
make test        # roda tudo com -race e gera coverage.out
# Fuzz tests
go test -fuzz=FuzzX -fuzztime=30s ./pkg/accept/store
```

### Tipos de testes que encontrarás

| Tipo | Onde | Exemplo |
|---|---|---|
| Unitários | junto do package | `pkg/accept/store` |
| Fuzz | `_fuzz_test.go` | `pkg/cli/pathguard_fuzz_test.go` |
| Benchmarks | `_benchmark_test.go` | `pkg/ingestion/ingestion_benchmark_test.go` |
| Testes de integridade | `test/security/` | `crypto_audit_test.go` |
| Fixtures | `testdata/` | audit log JSONL (ok/missing/tampered) |

### Fixtures de audit log

`testdata/fixtures/cpl/` contém fixtures que exercitam a verificação de integridade:
- `audit_log_ok.jsonl` — cadeia válida.
- `audit_log_missing.jsonl` — entrada em falta.
- `audit_log_tampered.jsonl` — hash adulterado.
- `audit_log_mismatch.jsonl` — mismatch.

Estes são excelentes exemplos de como testar **tamper-evidence**.

---

## 10. Guia para Juniors: por onde começar

> Recomenda-se seguir o **tour** do grafo de conhecimento para uma leitura guiada. Mas aqui vai o caminho essencial.

### Passo 1 — Perceber o "porquê" (alto nível)

Leia, nesta ordem:
1. `README.md` — visão, features, exemplos.
2. `doc/architecture/BUSINESS_VIEW.md` — por que o projeto existe.
3. `doc/architecture/CRYPTO_ARCHITECTURE.md` — a base criptográfica.
4. `doc/architecture/ENGINEERING_BLUEPRINT.md` — como está construído.

### Passo 2 — Perceber a entrada (main.go)

Comece por `main.go`:
- O `init()` (linhas 149-189) regista os 18 subcomandos — este é o "mapa" de todo o CLI.
- `runWardex` (199-412) mostra o **pipeline completo de gap analysis**. Segue-o com o debugger.

### Passo 3 — Conhecer os modelos de dados (`pkg/model`)

Antes de mexer em lógica, conheça os tipos centrais: `Control`, `Mapping`, `Finding`, `Vulnerability`, `GateReport`, `GapReport`. Tudo flui a partir daqui.

### Passo 4 — O heart: audit log encadeado

Entenda `internal/cpl` (hash canónico) e `pkg/audit` (cadeia). É a feature mais distintiva. Corra `wardex audit verify-chain` num fixture para ver em ação.

### Passo 5 — Mexer num subcomando simples

Comece com um comando pequeno (ex.: `keygen`). Veja como `cmd/keygen` delega para `pkg/trust`, e como se liga ao root em `main.go`.

---

### Mapa mental para tarefas típicas

| Se queres... | Vai para... |
|---|---|
| Mudar o release gate | `pkg/releasegate/`, `pkg/gate/`, `pkg/scorer/` |
| Adicionar um framework | `frameworks/` + `pkg/catalog/` (ver secção 11) |
| Alterar a verificação de integridade | `internal/cpl/`, `pkg/audit/` |
| Mexer em proveniência | `pkg/provenance/`, `pkg/attest/`, `pkg/trust/` |
| Alterar report | `pkg/report/` (markdown/json/csv/html) + `pkg/ui/` |
| Adicionar um comando CLI | criar `cmd/X`, delegar para `pkg/X`, registar em `main.go` |
| Mexer em persistência | `pkg/statestore/` (BLAKE3 chain) + `config/` |

---

## 11. Como adicionar um novo framework

O caminho completo para adicionar um catálogo de controlos:

1. **Criar o diretório** `frameworks/<novo-framework>/` com ficheiros YAML de controlos.
   - Cada controlo tem `id`, `title`, `description`, e mappings a domínios.
   - Veja `frameworks/iso27001/` como referência canónica.

2. **Registar no loader** `pkg/catalog/` — a função `Load(name)` deve conhecer o novo nome.
   - O loader é chamado com `--framework <novo-framework>`.

3. **Validar com ingestão** — o `pkg/ingestion` carrega os controlos. Verifique com `wardex assess`.

4. **Testar** — adicione fixtures de exemplo e um teste de correlação em `pkg/catalog`.

O passo 2 é o mais importante: sem registar no `catalog.Load`, o `--framework` vai falhar. Veja `catalog.Load` e o mapa de frameworks lá dentro.

---

## 12. Pitfalls e Dicas

### 12.1 Erros comuns

- **Esquecer o build tag `grpc`** — se mexer em provenance e o binary panic ao init, pode ser porque o driver gRPC pede `-tags grpc`.
- **Aceitar risco em exploração ativa** — o CRA Art. 14 **não pode** ser aceite. Não tente contornar.
- **Vulnerabilidades sem EPSS** — default para 1.0 (pior caso) e o gate pode bloquear inesperadamente. Corra `wardex enrich epss` primeiro.
- **Depender só de `cmd/`** — a lógica está em `pkg/`. `cmd/` é apenas orquestração Cobra.

### 12.2 Dicas de design

- **A lógica vive em `pkg/`, não em `cmd/`.** Mantenha `cmd/` fino.
- **CBOR determinístico** — para assinatura/hash, use sempre o mecanismo CBOR do `internal/cpl`, não formatos ad-hoc.
- **Path safety** — ao ler ficheiros do utilizador, use `pkg/cli.SafePath` (anti path-traversal) e `pkg/atomicwrite` para escrita atómica.
- **Adicione testes de integridade** sempre que tocar em hash/signature — o projeto valoriza `tamper-evidence`.

### 12.3 Changelog & release

- O `CHANGELOG.md` e os ficheiros `doc/releases/` mantêm o histórico de features por versão.
- O release é feito via GoReleaser (`.goreleaser.yaml`) com assinatura cosign e SBOM CycloneDX.

---

## 13. Convenções de Código

- **Linguagem:** Go 1.26+ (modernização para 1.27 com `strings.SplitSeq`, `range over int`).
- **CLI:** Cobra + pflag.
- **Canonicalização/hash:** CBOR determinístico via `fxamacker/cbor/v2`; hashing via SHA-256/BLAKE3.
- **Serialização cross-platform:** CDDL (RFC 8610) em `spec/cddl/`.
- **Lint:** `.golangci.yml` (golangci-lint).
- **Sinalização:** o projecto segue Conventional Commits (ver `doc/governance/GITFLOW_AI_GUIDE.md`).
- **Licença no topo dos ficheiros:** header SPDX `AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial`.
- **Blake3** (`lukechampine.com/blake3`) para chaining de estado; **Gleipnir** (`github.com/had-nu/gleipnir`) para consensus 3CP.

---

### Recursos adicionais

- **Grafo de conhecimento:** `.ua/knowledge-graph.json` (918 nós, 1586 arestas, 10 camadas, 12-passos tour) — explorável via dashboard do understand-anything.
- **Especificações internas:** `internal/SPEC_*.md`, `SPEC-WARDEX-HARDEN-CORDYCPS-BASED-v2.2.2.md`.
- **Playbooks:** `doc/operations/WARDEX_PLAYBOOK.md`, `WARDEX_TRUST_PLAYBOOK.md`, `EXIT_CODES.md`.
- **Arquitetura:** `doc/architecture/` (BUSINESS_VIEW, CRYPTO_ARCHITECTURE, ENGINEERING_BLUEPRINT, TECHNICAL_VIEW).

> Se encontrar um bug ou tiver uma ideia, adicione-a ao grafo/registo de ideas — e contribua com testes. A cobertura está em crescimento e cada teste valorizado.

