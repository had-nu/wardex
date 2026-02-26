<div align="center">
  <h1>Wardex</h1>
  <p><b>Gap Analysis, Risk-Based Release Gate e Business Impact — CLI Tool & Engine em Go</b></p>

  [![Go Report Card](https://goreportcard.com/badge/github.com/had-nu/wardex)](https://goreportcard.com/report/github.com/had-nu/wardex)
  [![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
</div>

Wardex é uma ferramenta de linha de comando (CLI) escrita em Go que ingere controlos de segurança já implementados na sua organização e os mapeia contra os 93 controlos da norma ISO/IEC 27001:2022 (Annex A).

Mais do que uma simples ferramenta de conformidade, o Wardex atua como um **Risk-Based Release Gate** nas suas pipelines de CI/CD. Em vez de bloquear lançamentos de software baseando-se em métricas binárias e estáticas (como "CVSS > 7.0"), o Wardex calcula o risco de lançamento real, ajustando a vulnerabilidade técnica ao impacto no negócio, exposição da infraestrutura, e controlos de compensação existentes.

## Porquê o Wardex?

Consulte a documentação em `/doc` para compreender a visão arquitetónica e os problemas de negócio que a ferramenta resolve:
- [A Visão de Negócio (BUSINESS_VIEW.md)](doc/BUSINESS_VIEW.md)
- [Arquitetura e Matemática Técnica (TECHNICAL_VIEW.md)](doc/TECHNICAL_VIEW.md)

## Compilação e Instalação

Assegure que tem o [Go (>= 1.21)](https://go.dev/doc/install) instalado.

```bash
git clone https://github.com/had-nu/wardex.git
cd wardex
go build -o wardex .
```

## Como Usar

O Wardex permite ingerir as políticas num formato simples YAML ou JSON, cruzar as vulnerabilidades (ex: output do Grype) num ficheiro alvo, e validar o gate:

```bash
./bin/wardex --config=test/testdata/wardex-config.yaml --gate=test/testdata/vulnerabilities.yaml test/testdata/dummy_controls.yaml
```

Isto gera relatórios visuais (em Markdown, CSV ou JSON) expondo a Análise de Maturidade das 4 áreas globais da ISO 27001 (Pessoas, Processos, Tecnológico e Físico) e executa as políticas de decisão (ALLOW / BLOCK) consoante o risco calibrado da organização.

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
