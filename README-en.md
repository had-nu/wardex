<div align="center">
  <h1>Wardex</h1>
  <p><b>Gap Analysis, Risk-Based Release Gate and Business Impact — CLI Tool & Engine in Go</b></p>

  [![Go Report Card](https://goreportcard.com/badge/github.com/had-nu/wardex)](https://goreportcard.com/report/github.com/had-nu/wardex)
  [![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

  <br>
  <a href="README-en.md">🇬🇧 English</a> | <a href="README-fr.md">🇫🇷 Français</a> | <a href="README-es.md">🇪🇸 Castellano</a> | <a href="README.md">🇵🇹 Português</a>
  <br><br>

  <img src="doc/banner.png" alt="Wardex Secure Release Gate Banner" width="800">
</div>

Wardex is a Command Line Interface (CLI) tool written in Go that ingests already implemented security controls in your organization and maps them against the 93 controls of the ISO/IEC 27001:2022 standard (Annex A).

More than just a simple compliance tool, Wardex acts as a **Risk-Based Release Gate** in your CI/CD pipelines. Instead of blocking software releases based on static binary metrics (like "CVSS > 7.0"), Wardex calculates the real release risk by adjusting technical vulnerability to business impact, infrastructure exposure, and existing compensating controls.

## Why Wardex?

Check the documentation in `/doc` to understand the architectural vision and the business problems the tool solves:
- [Business Vision (BUSINESS_VIEW.md)](doc/BUSINESS_VIEW.md)
- [Technical Architecture and Math (TECHNICAL_VIEW.md)](doc/TECHNICAL_VIEW.md)

## Build and Installation

Ensure you have [Go (>= 1.21)](https://go.dev/doc/install) installed.

### Option 1: Global Installation (Recommended)
You can install Wardex directly on your system, allowing you to run the `wardex` command anywhere:

```bash
go install github.com/had-nu/wardex@latest
```
*(Ensure the `$(go env GOPATH)/bin` directory is included in your `$PATH` or environment)*

### Option 2: Local Build from Source
If you prefer to clone the repository to test or develop locally:

```bash
git clone https://github.com/had-nu/wardex.git
cd wardex
go build -o wardex .
```

## Usage

Wardex allows you to ingest policies in a simple YAML or JSON format, cross-reference vulnerabilities (e.g., Grype output) in a target file, and validate the gate:

```bash
./bin/wardex --config=test/testdata/wardex-config.yaml --gate=test/testdata/vulnerabilities.yaml test/testdata/dummy_controls.yaml
```

This generates visual reports (in Markdown, CSV, or JSON) exposing the Maturity Analysis of the 4 global areas of ISO 27001 (People, Processes, Technological, and Physical) and executes decision policies (ALLOW / BLOCK) depending on the organization's calibrated risk.

## SDK Usage

The **Wardex** architecture was designed with a strong separation of concerns (in the `pkg/` directory). This means that besides using the CLI, Wardex can be imported as a library SDK in any other Go project, such as a REST API, a GRC orchestration service, or a bot.

Example of programmatic submission for *Risk-Based Release Gate* evaluation:

```go
package main

import (
	"fmt"

	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/releasegate"
)

func main() {
	// Configure the organization and asset context
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

	// Evaluate compost risk directly within your code
	report := gate.Evaluate(vulns)

	fmt.Printf("The Gate decision for this release was: %s\n", report.OverallDecision)
}
```

## Exception Management and Risk Acceptance

When Wardex blocks a release for exceeding the allowable risk appetite, organizations can manage exceptions formally and audibility through the `wardex accept` subcommand:

```bash
# Request risk acceptance for a blocked vulnerability
wardex accept request --report report.json --cve CVE-2024-1234 --accepted-by sec-lead@company.com --justification "Risk mitigated by external controls" --expires 30d

# Verify the cryptographic integrity of all active acceptances
wardex accept verify
```

Wardex guarantees the integrity of these exceptions using HMAC-SHA256 signatures, append-only audit logs (`JSONL`), and configuration drift detection.
