# Wardex Playbook

A comprehensive guide to using Wardex for compliance gap analysis and release gate evaluation.

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Core Concepts](#core-concepts)
4. [Scenarios](#scenarios)
5. [CI/CD Integration](#cicd-integration)
6. [API Reference](#api-reference)

---

## Installation

### From Source

```bash
git clone https://github.com/had-nu/wardex.git
cd wardex
go build -o bin/wardex .
```

---

## Quick Start

```bash
# Assessment
wardex ./controls.yaml --framework iso27001 -o markdown

# With Release Gate
wardex ./controls.yaml --gate ./vulns.yaml \
  --config ./wardex-config.yaml -o json
```

---

## Core Concepts

### Controls

```yaml
- id: CTRL-001
  name: Access Control Policy
  maturity: 4
  domains:
    - access_control
  evidences:
    - type: policy
      ref: https://internal.example.com/policy
```

### Frameworks

| Framework | Controls |
|-----------|----------|
| `iso27001` | 93 |
| `soc2` | 30 |
| `nis2` | 66 |
| `dora` | 35 |

---

## Scenarios

### Scenario 1: Basic Compliance Assessment

```bash
wardex ./controls.yaml --framework iso27001 -o markdown
```

---

### Scenario 2: Release Gate Evaluation

```yaml
# vulns.yaml
vulnerabilities:
  - cve_id: "CVE-2024-9901"
    cvss_base: 3.2
    epss_score: 0.018
    reachable: false
```

```bash
wardex ./controls.yaml \
  --config ./wardex-config.yaml \
  --gate ./vulns.yaml -o json
```

---

### Scenario 3: Blocking Critical

```bash
# Exit code 10 = BLOCK
wardex ./controls.yaml --gate ./critical-vulns.yaml
echo $?
```

---

### Scenario 4: SDK Usage

```go
import "github.com/had-nu/wardex/pkg/sdk"

controls, _ := sdk.LoadControls("./controls.yaml")
result, _ := sdk.Analyze(controls, "iso27001")
fmt.Printf("Coverage: %.1f%%\n", result.Summary.GlobalCoverage)
```

### Scenario 5: Convert Formats

```bash
wardex convert sbom ./sbom.xml
wardex convert grype ./grype.json
```

### Scenario 6: Standalone Evaluate

```bash
wardex evaluate --evidence ./vulns.yaml --config ./config.yaml ./controls.yaml
```

### Scenario 7: Risk Acceptance

```bash
wardex accept add CVE-2024-9999 --justification "WAF blocks" --expiry 90d
```

### Scenario 8: Snapshot/Trend

```bash
# Creates .wardex_snapshot.json on first run
wardex ./controls.yaml
# Second run shows delta
wardex ./controls.yaml
```

### Scenario 9: Multiple Frameworks

```bash
wardex ./controls.yaml --framework iso27001 -o iso.json
wardex ./controls.yaml --framework nis2 -o nis2.json
wardex ./controls.yaml --framework dora -o dora.json
```

### Scenario 10: Custom Thresholds

```yaml
# wardex-config.yaml
release_gate:
  enabled: true
  risk_appetite: 0.20
  warn_above: 0.12
  mode: any
  asset_context:
    criticality: 0.8
    internet_facing: true
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Compliance Gate
on: [push, pull_request]
jobs:
  wardex:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Wardex
        run: |
          go install github.com/had-nu/wardex@latest
          wardex ./controls.yaml --config ./config.yaml --gate ./vulns.yaml
```

---

## Exit Codes

| Code | Meaning |
|------|--------|
| 0 | Success / ALLOW |
| 1 | Error |
| 10 | BLOCKED |
| 11 | Compliance gap exceeds threshold |

---

*Generated for Wardex v1.7.2*