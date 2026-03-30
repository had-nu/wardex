<div align="center">
  <h1>Wardex</h1>
  <p><b>Gap Analysis, Risk-Based Release Gate e Business Impact — CLI Tool & Engine em Go</b></p>

  [![Wardex](https://img.shields.io/badge/Risk--based_Release-Wardex_v1.7.1-FF00FF?style=flat-square&logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiI+PHRleHQgeD0iMiIgeT0iMTQiIGZpbGw9IndoaXRlIiBmb250LXNpemU9IjE2IiBmb250LWZhbWlseT0ic2VyaWYiPs6pPC90ZXh0Pjwvc3ZnPgo=)](https://github.com/had-nu/wardex)
  ![Go](https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go&logoColor=white)
  [![Go Report Card](https://goreportcard.com/badge/github.com/had-nu/wardex?style=flat-square)](https://goreportcard.com/report/github.com/had-nu/wardex)
  [![CI Pipeline](https://github.com/had-nu/wardex/actions/workflows/ci.yml/badge.svg)](https://github.com/had-nu/wardex/actions/workflows/ci.yml)
  ![Coverage Gate](https://img.shields.io/badge/coverage-%E2%89%A570%25-brightgreen?style=flat-square)
  ![Security Hardened](https://img.shields.io/badge/Security-TeamPCP_Hardened-success?style=flat-square&logo=github-actions&logoColor=white)
  ![ISO-27001](https://img.shields.io/badge/Compliance-ISO_27001%3A2022-8A2BE2?style=flat-square&logo=checkmarx&logoColor=white)
  [![License: AGPL v3 / Commercial](https://img.shields.io/badge/License-Dual_Licensed-8A2BE2.svg?style=flat-square)](#licenciamento-e-uso-comercial)
  [![Powered by lazy.go](https://img.shields.io/badge/Powered_by-lazy.go-8A2BE2?style=flat-square&logo=go&logoColor=white)](https://github.com/had-nu/lazy.go)
  <br>
  <a href="README-en.md">English</a> | <a href="README-fr.md">Français</a> | <a href="README-es.md">Castellano</a> | <a href="README.md">Português</a>
  <br><br>

  <img src="doc/banner.png" alt="Wardex Secure Release Gate Banner" width="800">
</div>

> [!IMPORTANT]
> **Motivação TeamPCP (Attack Surface):** Após a campanha "TeamPCP", que transformou ferramentas de segurança em vetores de ataque contra pipelines diligentes, o Wardex priorizou e antecipou o seu roadmap de endurecimento defensivo. As atualizações recentes incluem pinning SHA256 de todas as Actions, isolamento rigoroso de permissões em workflows, integridade de CDNs via SRI e proveniência criptográfica para dados de enriquecimento. Uma nota de post-mortem detalhada será publicada em breve.



O Wardex é uma ferramenta de linha de comando (CLI) e Motor robusto escrito em Go que ingere controlos de segurança já implementados na sua organização e os mapeia contra múltiplos frameworks de conformidade global, incluindo os 93 controlos da norma ISO/IEC 27001:2022 (Annex A), SOC 2, NIS 2 e DORA.

Desenhado para ser utilizado tanto como uma CLI autónoma como um SDK integrável, o Wardex atua como um **Risk-Based Release Gate** nas suas pipelines de CI/CD. Em vez de bloquear lançamentos de software baseando-se em métricas binárias e estáticas (como "CVSS > 7.0"), o Wardex calcula o risco de lançamento real, ajustando a vulnerabilidade técnica ao impacto no negócio, exposição da infraestrutura, e controlos de compensação existentes.

## Porquê o Wardex?

Consulte a documentação em `/doc` para compreender a visão arquitetónica e os problemas de negócio que a ferramenta resolve:
- [A Visão de Negócio (BUSINESS_VIEW.md)](doc/BUSINESS_VIEW.md)
- [Arquitetura e Matemática Técnica (TECHNICAL_VIEW.md)](doc/TECHNICAL_VIEW.md)
- [Arquitetura de Não-Repudiação e Criptografia para Auditores (SOC 2, ISO 27001)](doc/wardex-g20-audit-readiness.md)
- [Casos de Uso Didáticos — 10 Cenários Completos com Inputs e Outputs Reais](doc/USECASES.md)

## Frameworks Suportados (a partir da v1.5.0)

O Wardex disponibiliza mapeamento nativo para os seguintes standards de conformidade (através da flag `--framework`):
- **ISO/IEC 27001:2022** (`iso27001` - predefinição)
- **SOC 2** (`soc2` - Trust Services Criteria)
- **NIS 2** (`nis2` - EU Directive 2022/2555)
- **DORA** (`dora` - Digital Operational Resilience Act)

## Licenciamento e Uso Comercial

O Wardex opera sob um modelo de **Duplo Licenciamento (Dual-Licensing)** para proteger a inovação open-source enquanto permite integrações proprietárias seguras.

1. **Uso Open-Source & Interno (Gratuito)**: Se utilizar o Wardex estritamente para as suas pipelines CI/CD internas, ou caso incorpore o Wardex num projeto e disponibilize o código desse projeto integralmente open-source, está coberto pela [AGPL-3.0](LICENSE).
2. **Uso Comercial & Incorporação SaaS (Pago)**: Se pretende embutir o motor do Wardex no backend de um produto comercial, plataforma SaaS corporativa, ou distribuí-lo de forma proprietária (sem abrir o seu código-fonte), **tem de adquirir uma Licença Comercial**. 

Para informações sobre Licenças Comerciais para a sua empresa, por favor leia os [Termos Comerciais Associados](doc/COMMERCIAL_LICENSE.md) ou contacte: **andre_ataide@proton.me**.

## Compilação e Instalação

Assegure que tem o [Go (>= 1.26)](https://go.dev/doc/install) instalado.

### Opção 1: Instalação Global (Recomendado)
Pode instalar o Wardex diretamente no seu sistema, permitindo executar o comando `wardex` em qualquer lugar:

```bash
go install github.com/had-nu/wardex@latest
```
*(Certifique-se que o diretório `$(go env GOPATH)/bin` está incluído no seu `$PATH` ou ambiente)*

### Opção 2: Compilação Local a partir do Código-Fonte
Se preferir clonar o repositório para testar ou desenvolver localmente:

```bash
git clone https://github.com/had-nu/wardex.git
cd wardex
make build
```

### Atualização para a Versão Mais Recente
Quando um novo patch ou versão minor for lançado (ex: `v1.1.1`), pode atualizar obtendo o código ou a tag mais recente e reconstruindo o binário:

```bash
# Para instalações globais
go install github.com/had-nu/wardex@latest

# Para builds locais (ex: escolher uma tag específica)
git fetch --tags
git checkout v1.7.1
make build
```

Por favor, consulte o [CHANGELOG.md](CHANGELOG.md) para detalhes sobre as notas de lançamento e correções de bugs.

## Como Usar

O Wardex permite ingerir as políticas num formato simples YAML ou JSON, cruzar as vulnerabilidades (ex: output do Grype ou SBOMs) num ficheiro alvo, e validar o gate:

```bash
./bin/wardex --config=test/testdata/wardex-config.yaml --gate=test/testdata/vulnerabilities.yaml test/testdata/dummy_controls.yaml
```

Isto gera relatórios visuais (em Markdown, CSV ou JSON) expondo a Análise de Maturidade das 4 áreas globais da ISO 27001 (Pessoas, Processos, Tecnológico e Físico) e executa as políticas de decisão (ALLOW / BLOCK / WARN) consoante o risco calibrado da organização.

## Integração com GitHub Actions (CI/CD)

Integrar o **Wardex** no GitHub Actions permite transformar sua pipeline num processo de **Governança de Risco** real. O Wardex atua como um "Release Gate" logo após os seus scans de segurança.

Veja um exemplo prático:

```yaml
# .github/workflows/wardex-gate.yml
jobs:
  risk-governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # Instalação Segura (v1.7.1)
      - name: Install Wardex
        run: |
          VERSION="v1.7.1"
          curl -sSL "https://github.com/had-nu/wardex/releases/download/${VERSION}/wardex_Linux_x86_64.tar.gz" | tar -xz
          sudo mv wardex /usr/local/bin/

      # Avaliação de Risco
      - name: Evaluate Risk Gate
        run: |
          wardex --config ./doc/examples/wardex-config.yaml \
                 --gate ./evidence.json \
                 ./doc/examples/policy-nis2.yaml \
                 --fail-above 0.9
```

Consulte os ficheiros de exemplo para configurar a sua pipeline:
- [Configuração de CI/CD (wardex-config.yaml)](doc/examples/wardex-config.yaml)
- [Exemplo de Política NIS2/ISO27001 (policy-nis2.yaml)](doc/examples/policy-nis2.yaml)

## Novidades (v1.7.0)

- **Enriquecimento EPSS c/ Human-in-the-Loop (HITL)**: Avaliações falhadas devido a vectores EPSS em falta (onde o Wardex assume "fail-close" 1.0) podem agora ser enriquecidas. O novo comando `wardex enrich epss` extrai probabilidades reais da API FIRST.org e encapsula-as como uma exceção criptográfica permitida pela pipeline.
- **Fail-Close Semântico Rigoroso**: O fallback de `0.05` para pontuações de vulnerabilidade desconhecidas foi revogado para `0.0` forçando atrito seguro. Sem dados concretos, a vulnerabilidade será invariavelmente classificada com risco máximo, acionando o pipeline *enrich*.

## Utilização como Biblioteca (SDK)

A arquitetura do **Wardex** foi desenhada com forte separação de responsabilidades (no diretório `pkg/`). Isto significa que além de utilizar o CLI, o Wardex pode ser importado como uma biblioteca (library) em qualquer outro projeto Go, como uma API REST, um serviço de orquestração GRC ou um bot.

Exemplo de submissão programática para avaliação por *Risk-Based Release Gate*:

```go
package main

import (
	"fmt"

	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/releasegate"
)

func main() {
	// Configure o contexto da organização e do ativo
	gate := releasegate.Gate{
		AssetContext: model.AssetContext{
			Criticality:    0.9,
			InternetFacing: true,
			RequiresAuth:   true,
		},
		CompensatingControls: []model.CompensatingControl{
			{Type: "waf", Effectiveness: 0.35},
		},
		RiskAppetite: 6.0,
	}

	vulns := []model.Vulnerability{
		{CVEID: "CVE-2024-1234", CVSSBase: 9.1, EPSSScore: 0.84, Reachable: true},
	}

	// Avalia o risco composto diretamente dentro do seu código
	report := gate.Evaluate(vulns)

	fmt.Printf("A decisão do Gate para este lançamento foi: %s\n", report.OverallDecision)
}
```

## Gestão de Exceções e Aceitação de Risco

Quando o Wardex bloqueia um lançamento por exceder o apetite de risco admissível, as organizações podem gerir exceções de forma formal e auditável através do subcomando `wardex accept`:

```bash
# Solicitar a aceitação de risco para uma vulnerabilidade bloqueada
wardex accept request --report report.json --cve CVE-2024-1234 --accepted-by sec-lead@company.com --justification "Risco mitigado por controlos externos" --expires 30d

# Verificar a integridade criptográfica de todas as aceitações ativas
wardex accept verify
```

O Wardex garante a integridade destas exceções utilizando assinaturas HMAC-SHA256, logs de auditoria append-only (`JSONL`) e deteção de alterações indesejadas na configuração (drift).

### Enriquecimento EPSS c/ Human-in-the-Loop (HITL)

Quando os seus *scanners* upstream omitem o EPSS, o Wardex **assume o pior caso (EPSS 1.0 = 100%)**, bloqueando a pipeline ate validacao explicita:

```bash
# Quando a CI bloquear por EPSS em falta:
wardex enrich epss wardex-vulns.yaml --output epss-enrich.yaml

# Na Pipeline, acople o signed payload:
wardex --epss-enrichment epss-enrich.yaml --gate vulns.yaml controls.json
```

O comando consulta a API da FIRST.org (`api.first.org`), obtém as probabilidades reais, e assina o resultado via HMAC-SHA256.

### Risco Contextual -- A Mesma CVE, 4 Decisoes

O Wardex calcula: `FinalRisk = (CVSS x EPSS) x (1 - Compensacoes) x Criticidade x Exposicao`

| CVE | CVSS | EPSS | [BANK] | [SAAS] | [DEV] | [HOSP] |
|---|---|---|---|---|---|---|
| **Log4Shell** | 10.0 | 0.94 | **14.2** `BLOCK` | **2.5** `BLOCK` | **0.3** `ALLOW` | **7.9** `BLOCK` |
| **xz backdoor** | 10.0 | 0.86 | **12.8** `BLOCK` | **2.3** `BLOCK` | **0.2** `ALLOW` | **7.1** `BLOCK` |
| **curl SOCKS5** | 9.8 | 0.26 | **3.9** `BLOCK` | **0.7** `ALLOW` | **0.1** `ALLOW` | **2.1** `BLOCK` |
| **minimist** | 9.8 | 0.01 | **0.1** `ALLOW` | **0.0** `ALLOW` | **0.0** `ALLOW` | **0.1** `ALLOW` |

Validado com **237 CVEs reais** e scores EPSS ao vivo da FIRST.org:

| Perfil | Apetite | BLOCK | ALLOW | % Block |
|---|---|---|---|---|
| [BANK] Banco Tier-1 (DORA) | 0.5 | **176** | 57 | 74% |
| [HOSP] Hospital (HIPAA) | 0.8 | **168** | 63 | 71% |
| [SAAS] Startup SaaS | 2.0 | **111** | 86 | 47% |
| [DEV] Dev Sandbox | 4.0 | **0** | 238 | 0% |

Relatorio completo: [EPSS Multi-Context Stress Test Report](doc/epss-stress-test-report.md)

## Gestão de Políticas Locais (Local Policy Management)

O Wardex permite a gestão granular de ficheiros de políticas por framework e por domínio (ex: ISO 27001) usando a sua própria sintaxe YAML. Em vez de criar ou editar manualmente ficheiros longos, utilize o subcomando `policy` para manipular os controlos de forma segura e com suporte a ferramentas de automação:

```bash
# Valida todos os ficheiros YAML garantindo a integridade do schema
wardex policy validate frameworks/iso27001/

# Lista o estado de conformidade de todos os controlos de forma legível
wardex policy list frameworks/iso27001/

# Upsert (adicionar ou atualizar) de um único controlo sem quebrar YAML manual
wardex policy add \
  --file frameworks/iso27001/technological_controls.yml \
  --id A.8.5 \
  --title "Secure authentication" \
  --status partial \
  --owner "Security Team" \
  --note "MFA enforced; hardware tokens pending rollout"
```

Isto garante que os ficheiros seguem sempre o _schema_ esperado, simplificando os processos de auditoria e integração nativa nos repositórios usando o Wardex como Governance-as-Code.

---

Mais detalhes de configuração no [Wardex Wiki: Risk-Based Gate Configurations](https://github.com/had-nu/wardex/wiki).
