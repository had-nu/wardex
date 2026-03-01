<div align="center">
  <h1>Wardex</h1>
  <p><b>Análisis de Brechas, Puerta de Liberación Basada en Riesgos e Impacto de Negocio — Herramienta CLI y Motor en Go</b></p>

  [![Wardex](https://img.shields.io/badge/Risk--based_Release-Wardex_v1-FF00FF?style=flat-square&logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiI+PHRleHQgeD0iMiIgeT0iMTQiIGZpbGw9IndoaXRlIiBmb250LXNpemU9IjE2IiBmb250LWZhbWlseT0ic2VyaWYiPs6pPC90ZXh0Pjwvc3ZnPgo=)](https://github.com/had-nu/wardex)
  ![Go](https://img.shields.io/badge/Made_with-Go-00ADD8?style=flat-square&logo=go&logoColor=white)
  [![Go Report Card](https://goreportcard.com/badge/github.com/had-nu/wardex?style=flat-square)](https://goreportcard.com/report/github.com/had-nu/wardex)
  ![ISO-27001](https://img.shields.io/badge/Compliance-ISO_27001%3A2022-8A2BE2?style=flat-square&logo=checkmarx&logoColor=white)
  [![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-8A2BE2.svg?style=flat-square&logo=gnu&logoColor=white)](https://www.gnu.org/licenses/agpl-3.0)
  [![Powered by lazy.go](https://img.shields.io/badge/Powered_by-lazy.go-8A2BE2?style=flat-square&logo=go&logoColor=white)](https://github.com/had-nu/lazy.go)

  <br>
  <a href="README-en.md">English</a> | <a href="README-fr.md">Français</a> | <a href="README-es.md">Castellano</a> | <a href="README.md">Português</a>
  <br><br>

  <img src="doc/banner.png" alt="Wardex Secure Release Gate Banner" width="800">
</div>

Wardex es una herramienta de Interfaz de Línea de Comandos (CLI) escrita en Go que procesa controles de seguridad ya implementados en su organización y los mapea contra los 93 controles de la norma ISO/IEC 27001:2022 (Anexo A).

Más que una simple herramienta de cumplimiento, Wardex actúa como una **Puerta de Liberación Basada en Riesgos (Risk-Based Release Gate)** en sus pipelines CI/CD. En lugar de bloquear lanzamientos de software basándose en métricas estáticas binarias (como "CVSS > 7.0"), Wardex calcula el riesgo real de liberación ajustando la vulnerabilidad técnica al impacto comercial, la exposición de la infraestructura y los controles compensatorios existentes.

## ¿Por qué Wardex?

Consulte la documentación en `/doc` para comprender la visión arquitectónica y los problemas empresariales que resuelve la herramienta:
- [Visión de Negocio (BUSINESS_VIEW.md)](doc/BUSINESS_VIEW.md)
- [Arquitectura Técnica y Matemáticas (TECHNICAL_VIEW.md)](doc/TECHNICAL_VIEW.md)

## Compilación e Instalación

Asegúrese de tener instalado [Go (>= 1.21)](https://go.dev/doc/install).

### Opción 1: Instalación Global (Recomendado)
Puede instalar Wardex directamente en su sistema, lo que le permite ejecutar el comando `wardex` en cualquier lugar:

```bash
go install github.com/had-nu/wardex@latest
```
*(Asegúrese de que el directorio `$(go env GOPATH)/bin` esté incluido en su `$PATH` o entorno)*

### Opción 2: Compilación Local desde el Código Fuente
Si prefiere clonar el repositorio para probar o desarrollar localmente:

```bash
git clone https://github.com/had-nu/wardex.git
cd wardex
go build -o wardex .
```

### Actualización a la Última Versión
Cuando se lance un nuevo parche o versión menor (ej: `v1.1.1`), puede actualizar obteniendo el código o etiqueta más reciente y reconstruyendo el binario:

```bash
# Para instalaciones globales
go install github.com/had-nu/wardex@latest

# Para builds locales (ej: elegir una etiqueta específica)
git fetch --tags
git checkout v1.1.1
go build -o wardex .
```

Por favor, consulte el [CHANGELOG.md](CHANGELOG.md) para obtener detalles sobre las notas de lanzamiento y parches.

## Uso

Wardex le permite integrar políticas en un formato YAML o JSON simple, cruzar vulnerabilidades (por ejemplo, salida de Grype) en un archivo objetivo y validar la puerta:

```bash
./bin/wardex --config=test/testdata/wardex-config.yaml --gate=test/testdata/vulnerabilities.yaml test/testdata/dummy_controls.yaml
```

Esto genera informes visuales (en Markdown, CSV o JSON) que exponen el Análisis de Madurez de las 4 áreas globales de ISO 27001 (Personas, Procesos, Tecnológico y Físico) y ejecuta políticas de decisión (ALLOW / BLOCK) según el riesgo calibrado de la organización.

## Uso como Biblioteca (SDK)

La arquitectura de **Wardex** fue diseñada con una fuerte separación de responsabilidades (en el directorio `pkg/`). Esto significa que, además de usar la CLI, Wardex puede importarse como un SDK de biblioteca en cualquier otro proyecto de Go, como una API REST, un servicio de orquestación de GRC o un bot.

Ejemplo de presentación programática para la evaluación de *Risk-Based Release Gate*:

```go
package main

import (
	"fmt"

	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/releasegate"
)

func main() {
	// Configurar el contexto de la organización y los activos
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

	// Evalúe el riesgo compuesto directamente dentro de su código
	report := gate.Evaluate(vulns)

	fmt.Printf("La decisión de la Puerta para este lanzamiento fue: %s\n", report.OverallDecision)
}
```

## Gestión de Excepciones y Aceptación de Riesgos

Cuando Wardex bloquea un lanzamiento por exceder el apetito de riesgo permisible, las organizaciones pueden gestionar excepciones formalmente y con auditabilidad a través del subcomando `wardex accept`:

```bash
# Solicitar la aceptación de riesgos para una vulnerabilidad bloqueada
wardex accept request --report report.json --cve CVE-2024-1234 --accepted-by sec-lead@company.com --justification "Riesgo mitigado por controles externos" --expires 30d

# Verificar la integridad criptográfica de todas las aceptaciones activas
wardex accept verify
```

Wardex garantiza la integridad de estas excepciones utilizando firmas HMAC-SHA256, registros de auditoría de solo adición (`JSONL`) y detección de deriva de configuración (drift).

---
<div align="center">
  <a href="https://github.com/had-nu/lazy.go"><img src="https://img.shields.io/badge/Powered_by-lazy.go-8A2BE2?style=flat-square" alt="Powered by lazy.go"></a>
</div>
