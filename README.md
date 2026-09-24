<div align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="pkg/ui/wardex-shield-dark.png">
  <img src="pkg/ui/wardex-shield.png" alt="Símbolo Wardex" width="256">
</picture>

<h1>WARDEX</h1>
<p><strong>Decisões de segurança e conformidade auditáveis</strong></p>
<p><em>Risk-based release governance para NIS2 · DORA · CRA · EU AI Act</em></p>

[![Go](https://img.shields.io/badge/Go-1.27-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/)
[![Go Report Card](https://goreportcard.com/badge/github.com/had-nu/wardex?style=flat-square)](https://goreportcard.com/report/github.com/had-nu/wardex)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io/had--nu/wardex-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/had-nu/wardex/pkgs/container/wardex)
[![Helm](https://img.shields.io/badge/Helm-v0.1.0-0F1689?style=flat-square&logo=helm&logoColor=white)](deploy/helm/wardex/)
[![GitHub Action](https://img.shields.io/badge/GitHub_Action-Wardex_Release_Gate-4A154B?style=flat-square&logo=githubactions&logoColor=white)](https://github.com/marketplace/actions/wardex-release-gate)
[![License: AGPL v3 / Commercial](https://img.shields.io/badge/License-AGPL_v3_|_Commercial-8A2BE2.svg?style=flat-square)](#licenciamento)

<br>
<a href="README-en.md">English</a> | <a href="README.md">Português</a>
<br><br>

</div>

> **Release actual:** `v2.6.0` · Go `1.27` · configuração schema `2`

> [!IMPORTANT]
> **CRA Article 14 (disponível desde v2.0; mantido em v2.6.0):** As obrigações de notificação por exploração activa do Cyber Resilience Act entram em vigor em setembro de 2026. O caminho actual correlaciona o catálogo CISA KEV, usa o exit code `12`, assina o artefacto com HMAC-SHA256 e regista os três prazos regulatórios. Este caminho não pode ser substituído por aceitações de risco.
>
> **EU AI Act (disponível desde v2.4.0; incluído em v2.6.0):** O Regulamento da Inteligência Artificial (UE 2024/1689) está disponível como framework de controlos. Os 31 controlos catalogados cobrem práticas proibidas, gestão de riscos, governação de dados, transparência, supervisão humana, exatidão/solidez/cibersegurança, obrigações de prestadores e implantadores, GPAI, acompanhamento pós-comercialização e comunicação de incidentes. Usa `--framework eu_ai_act` para avaliar a conformidade.

---

Wardex é uma CLI e biblioteca Go que transforma decisões de segurança e conformidade em evidência auditável. Opera em dois modos independentes — nenhum exige o outro.

**Posicionamento europeu:** O Wardex é construído de raiz para os regulamentos europeus — NIS2, DORA, CRA, **EU AI Act** — e para o padrão de compliance que está a emergir na UE. Cada decisão do release gate, cada aceitação de risco, cada artefacto Art14 é selado criptograficamente e registado num audit log encadeado que sobrevive a auditorias externas.

**Identidade visual:** a promessa, os tokens e as variantes de marca estão documentados em [BRANDING.md](doc/architecture/BRANDING.md).

---

## Audit Log Encadeado — Feature Principal

O audit log encadeado é o coração do Wardex. Cada entrada é ligada criptograficamente à anterior, formando uma cadeia inviolável de evidência.

```
┌─────────────┐    SHA-256    ┌─────────────┐    SHA-256    ┌─────────────┐
│  Entrada 1  │──────────────▶│  Entrada 2  │──────────────▶│  Entrada 3  │
│  (genesis)  │               │  (decisão)  │               │  (aceitação)│
└─────────────┘               └─────────────┘               └─────────────┘
       │                             │                             │
       ▼                             ▼                             ▼
  Config hash                 Config hash                   Config hash
  (CPL schema v2)                  (CPL schema v2)                   (CPL schema v2)
```

**O que torna inviolável:**
- Cada entrada inclui o hash da entrada anterior (hash encadeado)
- O hash da configuração (CPL) liga cada decisão à política em vigor
- Alterações ao audit log ou à configuração são detectadas imediatamente
- Exportável como JSONL para SIEM, Datadog, ou auditoria externa

```bash
# Verificar integridade da cadeia
wardex audit verify-chain --audit-log wardex-gate-audit.log

# Verificar ligação com configurações arquivadas
wardex audit verify-link --audit-log wardex-gate-audit.log --config-archive ./configs/

# Export paginado para SIEM
wardex audit export --audit-log wardex-gate-audit.log --format jsonl --limit 500
```

---

## What's New — v2.6.0 (2026-09-15)

A linha actual é a **v2.6.0** e mantém compatibilidade com os formatos legados.

**Cadeia CPL e provenance (P0/L1/L4/L5):**
- `config_schema_version: 2` e `cpl_schema_version` explícitos; a cadeia usa
  `previous_entry_hash` canónico e `wardex audit verify-chain` faz streaming.
- `wardex audit export --limit N [--cursor <sha256>] [--tail]` exporta JSONL/CSV
  para SIEM com paginação e metadados de cursor.
- `wardex gate check-version --audit-log ... --version 2.6.0` impede selar a
  mesma versão duas vezes (`13 = DuplicateRelease`). Em release-seal,
  `--release-version` exige `--policy-ref`.

**Gate e evidência (L3/L7):**
- `--gate-class pr|deploy|nightly` com severidades `block|advisory|off`;
  freshness apenas advisory devolve `6 = FreshnessAdvisory`.
- `release_gate.forced_upgrade.{enabled,deadline,tripwire_failures}` e as flags
  `--forced-upgrade` / `--forced-upgrade-state` activam o tripwire de
  evidência. O estado fica em `.wardex/forced_upgrade.json`.

**Chaves e Article 14 (L2/L6):**
- `wardex keygen --encrypt` cria envelopes `WARDEX-KEY-V1` (Argon2id +
  AES-256-GCM); a passphrase pode vir de `--passphrase` ou
  `WARDEX_KEY_PASSPHRASE`. Keyrings plaintext legados continuam válidos.
- Artefactos Art14 levam `format_version` e `capabilities`; versões futuras são
  rejeitadas sem downgrade silencioso. Schemas: `spec/cddl/`.

**Interface terminal (main actual):**
- Dashboards TTY para os comandos de avaliação, governança e verificação;
  JSON/CSV/pipes/CI permanecem machine-oriented e sem decoração.
- `NO_COLOR`, `TERM=dumb`, `COLUMNS`, `CI`, `GITHUB_ACTIONS` e `GITLAB_CI`
  controlam o fallback. A especificação está em
  [`doc/architecture/TERMINAL_UI.md`](doc/architecture/TERMINAL_UI.md).

**Novos exit codes:** `6 = FreshnessAdvisory` e `13 = DuplicateRelease`.

> Padrões de desenho deste release inspirados no ecossistema Nym (Apache-2.0) —
> usados como referência, sem cópia de código. Ver [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md).

---

## Historical foundations — v2.3.0 / v2.4.0

**CBOR Deterministic Canonicalization (v2.3.0):**
- Toda a canonicalização para assinatura migrou de formatos ad-hoc para CBOR
  Core Deterministic Encoding (RFC 8949 §4.2.3) via `fxamacker/cbor/v2`
- CPL config hash, WexState seal message, e tool attestation usam o mesmo
  mecanismo determinístico, garantindo byte-identicidade entre plataformas

**CDDL Schemas (v2.3.0):**
- `spec/cddl/` define formalmente CPL audit entries, WexState envelopes,
  e 3CP tool attestations em CDDL (RFC 8610)
- Servem como fonte da verdade para serialização e confluência entre
  implementações

**3CP Tool Provenance Attestation (v2.3.0):**
- `pkg/attest/` — atestação Ed25519 + CBOR determinístico para provenance
  de ferramentas (grype, sbom, kev)
- Interface `Anchorer` abstrai o backend 3CP (Gleipnir embedded, gRPC, noop)
- `--attest` flag nos converters + `wardex provenance attest` CLI

**EU AI Act Framework (v2.4.0):**
- Catálogo completo do Regulamento (UE) 2024/1689: práticas proibidas, gestão de riscos, governação de dados, documentação técnica, transparência, supervisão humana, exatidão/solidez/cibersegurança, obrigações de prestadores e implantadores, avaliação de impacto sobre direitos fundamentais, GPAI, acompanhamento pós-comercialização, comunicação de incidentes
- Usar: `wardex --framework eu_ai_act ./frameworks/eu_ai_act/*.yml`

**Gleipnir Provenance Anchoring:**
- Prova de integridade imutável para artefactos de release via `wardex provenance seal`
- Suporte a embedded consensus engine (gleipnir-embedded) ou servidor gRPC remoto
- Chain seal com SHA-256 de todos os artefactos + âncora criptográfica

**Isolamento do driver gRPC:**
- O driver de proveniência gRPC (com protobuf) foi isolado atrás da build tag `grpc` para evitar panic ao init. Para usar: `go build -tags grpc`.

---

## Frameworks e workflows

**Frameworks seleccionáveis:** ISO/IEC 27001:2022 · SOC 2 · NIS 2 · DORA · NIST CSF 2.0 · **EU AI Act**

**Workflows regulamentares:** CRA Article 14, aceitações de risco, provenance, audit log encadeado e release governance.

```bash
wardex assess controls.yaml --framework iso27001     # predefinição
wardex assess controls.yaml --framework nis2
wardex assess controls.yaml --framework dora
wardex assess controls.yaml --framework eu_ai_act
```

---

## Instalação

```bash
# Versão actual
go install github.com/had-nu/wardex/v2@v2.6.0

# Último tag publicado
go install github.com/had-nu/wardex/v2@latest
```

Requer Go ≥ 1.27. Confirma que `$(go env GOPATH)/bin` está no teu `$PATH`.

Para compilar a partir do código-fonte:

```bash
git clone https://github.com/had-nu/wardex.git
cd wardex && make build
```

### Docker

```bash
docker pull ghcr.io/had-nu/wardex:2.6.0
```

### Helm (Kubernetes)

```bash
helm upgrade --install wardex deploy/helm/wardex/ \
  --set acceptSecret.value=$(openssl rand -hex 32)
```

Consulta [deploy/helm/wardex/](deploy/helm/wardex/) para a referência completa do chart. O chart `0.1.0` usa a aplicação `v2.6.0`.

---

## Quickstart

### 1. Avaliar risco de vulnerabilidades

```bash
# Converter output do Grype para formato Wardex
wardex convert grype test/usability/grype-results.json > vulns.yaml

# Avaliar com contexto do activo
wardex evaluate \
  --evidence vulns.yaml \
  --config doc/examples/wardex-config.yaml \
  test/testdata/documented-controls.yaml

# Dry-run — pré-visualizar sem escrever artefactos
wardex evaluate --evidence vulns.yaml --config doc/examples/wardex-config.yaml \
  test/testdata/documented-controls.yaml --dry-run
```

### 2. Gerar e gerir chaves

```bash
# Gerar chave Ed25519 para o sistema de confiança
wardex keygen

# Opcional: usar em vez de `keygen` para criar um envelope encriptado
WARDEX_KEY_PASSPHRASE="$(openssl rand -base64 32)" wardex keygen --encrypt

# A chave é criada em ~/.crypto/trust/root.key
# A pública é ~/.crypto/trust/root.key.pub (enviar ao admin)
```

### 3. Selar e verificar provenance

```bash
# Selar diretório de artefactos com Gleipnir (v2.6.0; compatível com v2.4.0+)
wardex provenance seal \
  --dir ./dist \
  --output chain-seal.json \
  --label "release-v2.6.0"

# Verificar integridade
wardex provenance verify <chain-hash>
```

**Exit codes:** `0` OK · `1` erro genérico · `3` integridade · `4` store inconsistente · `5` expiração próxima · `6` freshness advisory · `10` BLOCK · `11` compliance fail · `12` exploração activa · `13` release duplicada

---

## Interface do terminal

Em terminais interativos, os comandos de avaliação, `art14`, `simulate`, `keygen`, `config`, `provenance`, `chain`, `hmac`, `audit`, `enrich`, `convert`, `assets`, `auth`, `contract`, `policy`, `state`, `gate`, `accept` e `trust` apresentam a execução como um dashboard textual com:

- cabeçalho e versão;
- cartão da sessão e parâmetros efetivos;
- fases reais do pipeline (`RUNNING`, `DONE`, `SKIPPED` e `FAILED`);
- cards dos gaps/decisões mais relevantes;
- resumo de coverage, severidade e decisão do release gate.

A interface é ativada automaticamente apenas quando o destino é um TTY. Saídas JSON, CSV, pipes, ficheiros e CI permanecem limpas e sem decoração. Campos potencialmente sensíveis são apresentados como `[REDACTED]`. O `audit export` mantém o seu formato de streaming machine-oriented para preservar JSONL/CSV e metadados de paginação.

Variáveis de ambiente reconhecidas:

- `NO_COLOR` — desativa cores;
- `TERM=dumb` — usa fallback ASCII;
- `COLUMNS` — largura alternativa quando o terminal não a fornece;
- `CI`, `GITHUB_ACTIONS` e `GITLAB_CI` — desativam a interface decorativa.

Para saída estruturada, use um ficheiro ou redirecionamento, por exemplo:

```bash
NO_COLOR=1 wardex --output json controls.yaml > report.json
wardex evaluate --evidence vulns.yaml --config wardex-config.yaml
```

A especificação completa do layout está em [`doc/architecture/TERMINAL_UI.md`](doc/architecture/TERMINAL_UI.md).

---

## Comandos principais

O comando raiz `wardex <inputs>` executa a análise de gaps; os subcomandos
abaixo aprofundam as operações de gate, governança, evidência e verificação.

| Comando | Descrição |
|---------|-----------|
| `wardex` | Análise de gaps contra um framework e, opcionalmente, release gate |
| `wardex assess` | Avaliação de conformidade com inventário de activos e layer delta |
| `wardex evaluate` | Gate de release sobre um ficheiro de vulnerabilidades |
| `wardex aggregate` | Combina resultados de gate numa decisão única |
| `wardex convert grype/sbom/kev` | Converte outputs de terceiros para o formato Wardex |
| `wardex enrich epss` | Busca e assina scores EPSS em falta |
| `wardex accept` | Pedidos, revogação, expiração, verificação e aceitação de exploração activa |
| `wardex auth status/verify` | Estado do trust store e permissões do actor |
| `wardex contract verify` | Integridade SHA-256 de contratos |
| `wardex policy` | `validate`, `list`, `add` e `check-expiry` de políticas |
| `wardex state` | Estado persistente: `status`, `history`, `trend`, `dashboard`, `verify`, `cleanup` |
| `wardex gate check-version` | Guard anti-re-release; devolve `13` para duplicados |
| `wardex art14` | `list`, `show`, `mark-dispatched`, `finalize` e `verify` |
| `wardex provenance` | `seal`, `submit`, `attest`, `verify` e `status` via 3CP |
| `wardex config` | `hash`, `seal` e `show` de configuração |
| `wardex audit` | `verify-chain`, `verify-link` e `export` SIEM com cursor |
| `wardex trust` | `init`, `add`, `revoke`, `list`, `show` e `verify` |
| `wardex keygen` | Geração de chaves Ed25519, com `--encrypt` opcional |
| `wardex chain seal` | Selo SHA-256 para artefactos |
| `wardex hmac sign` | Assinatura HMAC-SHA256 de ficheiros |
| `wardex assets inventory` | Inventário ICT |
| `wardex simulate` | Simulador interactivo de decisões |

O shell também disponibiliza `wardex completion` para completar comandos.

---

## Release Gate Baseado em Risco

### Configuração

```yaml
# wardex-config.yaml
config_schema_version: 2
release_gate:
  enabled: true
  risk_appetite: 0.20
  warn_above: 0.12
  mode: any               # "any" bloqueia por vulnerabilidade; "aggregate" usa soma
  classes:
    pr:
      freshness: advisory
    deploy:
      freshness: block
    nightly:
      freshness: advisory
  forced_upgrade:
    enabled: false
    deadline: "2026-09-24"
    tripwire_failures: 5
  asset_context:
    criticality: 0.8
    internet_facing: true
    requires_auth: true
  compensating_controls:
    - type: waf
      effectiveness: 0.35
```

### A mesma CVE, quatro contextos

Heatmap de risco: cada célula mostra o **score de risco** (exposição do contexto × EPSS) e a **decisão do gate** para as mesmas CVE em quatro contextos. Quanto mais quente a cor, maior o score.

| CVE | CVSS | EPSS | [BANK] | [SAAS] | [INFRA] | [HOSP] |
|---|---|---|---|---|---|---|
| Log4Shell | 10.0 | 0.94 | 🟥 **1.41 BLOCK** | 🟧 **0.75 BLOCK** | 🟥 **1.41 BLOCK** | 🟥 **1.13 BLOCK** |
| xz backdoor | 10.0 | 0.86 | 🟥 **1.29 BLOCK** | 🟧 **0.69 BLOCK** | 🟥 **1.29 BLOCK** | 🟥 **1.03 BLOCK** |
| curl SOCKS5 | 9.8 | 0.26 | 🟨 **0.38 BLOCK** | 🟨 **0.20 WARN** | 🟨 **0.38 BLOCK** | 🟨 **0.31 BLOCK** |
| minimist | 9.8 | 0.01 | 🟩 **0.01 ALLOW** | 🟩 **0.01 ALLOW** | 🟩 **0.01 ALLOW** | 🟩 **0.01 ALLOW** |

**Legenda (intensidade do score):** 🟩 < 0.20 · 🟨 0.20–0.49 · 🟧 0.50–0.99 · 🟥 ≥ 1.00

> Não existe uma decisão de release universal: Log4Shell e o backdoor xz bloqueiam em **todos** os contextos (score alto sob qualquer exposição); o curl SOCKS5 (EPSS 0.26) fica **WARN no limite do apetite de risco no SaaS** (0.20) mas **BLOCK** em contextos bancário/infra; o minimist é residual e passa em todos. O heatmap mostra como a mesma CVE agrega risco diferente consoante a exposição — por isso o gate é avaliado **por contexto**, não como "uma decisão para todos".

### Enriquecimento EPSS

```bash
wardex enrich epss wardex-vulns.yaml --output epss-enrich.yaml
wardex evaluate --epss-enrichment epss-enrich.yaml --evidence vulns.yaml controls.yaml
```

### Integração CI/CD

```yaml
# .github/workflows/wardex-gate.yml
jobs:
  risk-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Wardex
        run: go install github.com/had-nu/wardex/v2@v2.6.0
      - name: Guard duplicate release
        run: wardex gate check-version --audit-log wardex-gate-audit.log --version "${GITHUB_REF_NAME#v}"
      - name: Evaluate risk gate
        run: |
          wardex evaluate \
            --config .wardex/config.yaml \
            --evidence vulns.yaml \
            --gate-class deploy \
            controls.yaml
```

---

## Análise de Gaps de Conformidade

O Wardex compara o que o infosec declarou com o que está operacionalmente activo, e identifica o delta em relação ao framework.

| Categoria | Significado |
|---|---|
| **Coberto** | Presente na camada `implemented`, maturidade >= 3, com evidência operacional. |
| **Política sem execução** | Documentado apenas. Nenhum controlo implementado correspondente. |
| **Prática sem governação** | Implementado mas sem política documentada. |
| **Lacuna** | Ausente em ambas as camadas para um controlo do catálogo. |

```bash
wardex assess documented-controls.yaml implemented-controls.yaml \
  --framework iso27001 \
  -o markdown

# Com inventário de activos
wardex assess documented-controls.yaml implemented-controls.yaml \
  --assets assets.yaml \
  --framework iso27001 \
  -o json --out-file posture.json
```

---

## CRA Article 14

As obrigações de notificação por exploração activa do Regulamento Europeu de Resiliência Cibernética entram em vigor em setembro de 2026.

**Active Exploitation Hard Stop:** Quando uma vulnerabilidade é classificada como activamente explorada (`actively_exploited: true`), o `wardex evaluate` termina com código **12** — distinto do bloqueio normal (10). Não pode ser substituído por aceitações de risco.

```bash
# Artefacto Art14
wardex art14 list
wardex art14 show <artefact-id>
wardex art14 verify <artefact-id>
wardex art14 mark-dispatched <artefact-id> --phase early-warning

# Aceitação de exploit activo
wardex accept active-exploit --cve CVE-2024-3094 --justification "..." --art14-artefact wardex-art14-....json
```

Consulta o [Playbook de Governação](doc/operations/WARDEX_TRUST_PLAYBOOK.md) para o fluxo completo.

---

## EU AI Act (Regulamento da Inteligência Artificial)

O Regulamento (UE) 2024/1689 — EU AI Act — está disponível como framework de controlos no Wardex desde v2.4.0 e integra a CLI actual v2.6.0. São 31 controlos catalogados que cobrem as obrigações aplicáveis a sistemas de IA de risco elevado, modelos de IA de finalidade geral (GPAI) e práticas proibidas.

### Controlos por domínio

| Domínio | Controlos | Artigos |
|---|---|---|
| Prohibited practices | 1 | Art 5 |
| Governance & classification | 4 | Arts 6, 21, 49, 99 |
| Risk management | 1 | Art 9 |
| Data governance | 1 | Art 10 |
| Documentation & records | 4 | Arts 11, 12, 18, 19 |
| Transparency | 2 | Arts 13, 50 |
| Human oversight | 1 | Art 14 |
| Technical (accuracy, robustness, security) | 2 | Arts 15, 19 |
| Provider obligations | 2 | Arts 16, 20 |
| Quality management | 1 | Art 17 |
| Deployer obligations | 2 | Arts 26, 27 |
| Value chain (importer, distributor, rep) | 4 | Arts 22, 23, 24, 25 |
| Conformity assessment | 2 | Arts 43, 47 |
| GPAI (general-purpose AI) | 2 | Arts 53, 55 |
| Post-market & incident reporting | 2 | Arts 72, 73 |

```bash
# Avaliar conformidade com EU AI Act
wardex --framework eu_ai_act ./frameworks/eu_ai_act/*.yml

# Listar controlos do catálogo
wardex --framework eu_ai_act --output json ./frameworks/eu_ai_act/*.yml
```

### Proveniência 3CP com Gleipnir

Cada release pode ser selado criptograficamente com o Gleipnir embedded consensus engine.
O Wardex abstrai o backend 3CP através da interface `Anchorer` — Gleipnir é a referência,
mas qualquer motor 3CP compatível funciona.

```bash
# Selar artefactos de release
wardex provenance seal \
  --dir ./dist \
  --output chain-seal.json \
  --label "wardex-v2.6.0"

# Ancorar commit de tag
wardex provenance submit $(git rev-parse v2.6.0) --label "git-tag-v2.6.0"

# Atestar provenance de ferramenta (v2.3.0+)
wardex provenance attest input.txt --tool my-scanner --version 1.0 --sign-key key.wex

# Converter e atestar num passo
wardex convert grype grype-output.json --attest key.wex

# Verificar estado da cadeia
wardex provenance status
```

---

## Gestão de Chaves & Governação

### Chaves Criptográficas

Todas as chaves Ed25519 são armazenadas em `~/.crypto/` com subdiretórios por finalidade:

```
~/.crypto/
├── provenance/          # Assinatura de manifestos de provenance + atestações 3CP
│   ├── signing.key      # Ed25519 privada (mode 0400)
│   └── signing.key.pub  # Ed25519 pública
└── trust/               # Sistema de confiança wardex
    └── root.key         # Chave raiz (gerada por wardex keygen)
```

**Permissões**: Directórios `700`, chaves privadas `0400`, chaves públicas `0644`.

### Verificação de Provenance

Na linha actual v2.6.0, usar o Gleipnir embedded com CBOR deterministic attestation:

```bash
# Verificar chain seal de release
wardex provenance verify <chain-hash>

# Verificar estado da cadeia
wardex provenance status

# Verificar atestação de ferramenta
# (o .attest é CBOR determinístico, verificável com qualquer implementação 3CP)
```

Para releases legados (v2.2.2 e anteriores), a chave pública abaixo permite verificar o manifesto de proveniência:

> **Chave pública de assinatura (v2.2.2):**
> ```
> ed25519:HsD9e6BB2LlaeKODGqgWUZoflDgdUH1HWTdyWA7dGqE=
> ```

> **Root hash (BLAKE3, 113 ficheiros):**
> ```
> sha256:6f972edf99f5457f8fb13668c529f4343dab7a76d20b67ea746ebdf54d910fee
> ```

### Trust Store & Sealed Config (WexState)

Para conformidade **DORA** e cadeias de custódia não-repudiáveis:

- **Identidade forte**: Chaves Ed25519 para Admins, CISOs e Analistas.
- **Sealed config**: As políticas de risco não podem ser alteradas sem aprovação executiva.
- **Trust store append-only**: Registo central de chaves autorizadas e revogações.

```bash
# Sela a política (acção do CISO)
wardex config seal --keyring ~/.crypto/trust/root.key --input config.yaml --out config.wexstate

# Avalia com verificação obrigatória do selo
wardex evaluate --config config.wexstate --evidence vulns.yaml --strict
```

---

## Environment

| Variável | Predefinição | Descrição |
|---|---|---|
| `WARDEX_ACCEPT_SECRET` | — | Segredo HMAC-SHA256 para assinaturas de aceitação e Art14 (mínimo 32 caracteres) |
| `WARDEX_ACTOR` | `USER` | Identidade registada na auditoria; `GITHUB_ACTOR` tem precedência quando definido |
| `WARDEX_KEY_PASSPHRASE` | — | Passphrase para envelopes `WARDEX-KEY-V1` |
| `WARDEX_TRUST_STORE` | `./wardex-trust.yaml` | Referência da trust store |
| `WARDEX_RELEASE_VERSION` | — | Versão para o modo release-seal; também pode ser fornecida com `--release-version` |
| `WARDEX_POLICY_REF` | — | Referência de política exigida com `WARDEX_RELEASE_VERSION` |

---

## SDK

```go
import "github.com/had-nu/wardex/v2/pkg/sdk"

controls, _ := sdk.LoadControls("./controls.yaml")
result, _   := sdk.Analyze(controls, "iso27001")

fmt.Printf("Coverage: %.1f%%\n", result.Summary.GlobalCoverage)
```

Para o release gate:

```go
import (
    "github.com/had-nu/wardex/v2/pkg/model"
    "github.com/had-nu/wardex/v2/pkg/releasegate"
)

gate := releasegate.Gate{
    AssetContext: model.AssetContext{
        Criticality:    0.9,
        InternetFacing: true,
        RequiresAuth:   true,
    },
    CompensatingControls: []model.CompensatingControl{
        {Type: "waf", Effectiveness: 0.35},
    },
    RiskAppetite: 0.20,
    Mode:         "any",
}

report := gate.Evaluate([]model.Vulnerability{
    {CVEID: "CVE-2024-1234", CVSSBase: 9.1, EPSSScore: 0.84, Reachable: true},
})

fmt.Println(report.OverallDecision) // ALLOW | WARN | BLOCK
```

---

## Documentação

- [Identidade visual e branding](doc/architecture/BRANDING.md)
- [Terminal UI](doc/architecture/TERMINAL_UI.md)
- [Arquitectura e funcionamento interno](doc/architecture/TECHNICAL_VIEW.md)
- [Contexto de negócio e o problema do gate binário](doc/architecture/BUSINESS_VIEW.md)
- [Arquitectura Criptográfica (CBOR, CDDL, 3CP)](doc/architecture/CRYPTO_ARCHITECTURE.md)
- [REC + Provenance — Plano de Mitigação](doc/architecture/REC_PROVENANCE_ENHANCEMENT.md)
- [Playbook — casos de uso com comandos completos](doc/operations/WARDEX_PLAYBOOK.md)
- [Governação — Trust Store & Sealed Config Playbook](doc/operations/WARDEX_TRUST_PLAYBOOK.md)
- [Integração com GitHub Actions](doc/operations/github-actions-integration.md)
- [Helm chart (referência)](deploy/helm/wardex/)
- [Exit codes](doc/operations/EXIT_CODES.md)
- [Migração CBOR v2.3.0](internal/doc/CBOR_MIGRATION_v2.3.0.md)
- [Esquemas CDDL](spec/cddl/)
- [Ambiente de desenvolvimento (docker-compose)](docker-compose.yml)
- [CHANGELOG](CHANGELOG.md)
- [Release notes v2.6.0](doc/releases/v2.6.0-notes.md)
- [Contribuir](CONTRIBUTING.md)

---

## Licenciamento

Duplo licenciamento:

**AGPL-3.0 (gratuito):** uso em pipelines CI/CD internas ou em projectos open-source que disponibilizem o código-fonte.

**Licença comercial (pago):** integração em produtos proprietários, plataformas SaaS, ou distribuição sem abertura do código-fonte. Consulta os [Termos Comerciais](doc/governance/COMMERCIAL_LICENSE.md) ou contacta **andre_ataide@proton.me**.

**Atribuições / Proveniência:** algumas funcionalidades seguem padrões de desenho do ecossistema Nym (Apache-2.0), como referência e sem cópia de código. Ver [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md).
