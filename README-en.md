<h1 align="center">Wardex — The CRA-Ready Release Gate for NIS2 &amp; DORA</h1>

<div align="center">

![Wardex Lockup](pkg/ui/wardex-lockup.svg)

[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/)
[![Go Report Card](https://goreportcard.com/badge/github.com/had-nu/wardex?style=flat-square)](https://goreportcard.com/report/github.com/had-nu/wardex)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io/had--nu/wardex-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/had-nu/wardex/pkgs/container/wardex)
[![GitHub Action](https://img.shields.io/badge/GitHub_Action-Wardex_Release_Gate-4A154B?style=flat-square&logo=githubactions&logoColor=white)](https://github.com/marketplace/actions/wardex-release-gate)
[![License: AGPL v3 / Commercial](https://img.shields.io/badge/License-AGPL_v3_%7C_Commercial-8A2BE2.svg?style=flat-square)](#licensing)

<br>
<a href="README-en.md">English</a> | <a href="README.md">Português</a>
<br><br>

</div>

> [!IMPORTANT]
> **CRA Article 14 (v2.0):** The Cyber Resilience Act's active exploitation notification obligations enter into force in September 2026. Wardex v2.0 implements the full path: CISA KEV catalogue correlation, a distinct exit code (`12`), an HMAC-SHA256 signed notification artefact, and a chained audit entry with the three regulatory deadlines. This path cannot be overridden by risk acceptances.

---

Wardex is a CLI and Go library that turns security and compliance decisions into auditable evidence. Two independent modes — neither requires the other.

The release gate evaluates each vulnerability in the context of the asset that contains it: system criticality, effective exposure, compensating controls already active. Rather than a static CVSS threshold that blocks everything or nothing, the output is a decision with a timestamped, signed record that survives an audit.

The gap analysis crosses what the security function declared against what is operationally confirmed, mapped against the chosen framework catalogue. The result is not a control list — it is the separation between genuine coverage, what exists only in policy, and what operates outside of governance.

---

## Supported frameworks

ISO/IEC 27001:2022 · SOC 2 · NIS 2 · DORA · CRA Article 14 · NIST CSF 2.0

```bash
wardex assess controls.yaml --framework iso27001  # default
wardex assess controls.yaml --framework nis2
wardex assess controls.yaml --framework dora
```

---

## Installation

```bash
go install github.com/had-nu/wardex@95eed886
```

Requires Go ≥ 1.26. Ensure `$(go env GOPATH)/bin` is in your `$PATH`.

To build from source:

```bash
git clone https://github.com/had-nu/wardex.git
cd wardex && make build
```

---

## Quickstart

Test Wardex with the example files included in the repository:

```bash
# Convert Grype output to Wardex format
wardex convert grype test/usability/grype-results.json > vulns.yaml

# Evaluate with asset context
wardex evaluate \
  --evidence vulns.yaml \
  --config doc/examples/wardex-config.yaml

# Exit codes: 0 (ALLOW) · 10 (BLOCK) · 11 (Gap) · 12 (Active exploitation)
```

---

## CRA Article 14 (v2.0)

The EU Cyber Resilience Act's active exploitation notification obligations enter into force in September 2026. Wardex v2.0 implements the Article 14 reporting path.

### KEV Correlation

```bash
# Download the CISA KEV catalogue
curl -sSL https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json -o kev-catalogue.json

# Convert Grype output with KEV correlation
wardex convert grype grype-output.json --kev kev-catalogue.json
```

### Active Exploitation Hard Stop

When a vulnerability is classified as actively exploited (`actively_exploited: true`), `wardex evaluate`:
- Exits with code **12** (`ActivelyExploited`) — distinct from the normal gate block (10)
- Generates an Article 14 notification artefact signed with HMAC-SHA256
- Records a chained audit entry with three CRA deadlines
- **Cannot** be overridden by risk acceptances

```bash
wardex evaluate --evidence vulns.yaml --config wardex-config.yaml frameworks/iso27001/*.yml
```

### Artefact Lifecycle (`wardex art14`)

```bash
wardex art14 list
wardex art14 show <artefact-id>
wardex art14 verify <artefact-id>
wardex art14 mark-dispatched <artefact-id> --phase early-warning
wardex art14 finalize <artefact-id> --patch-date 2026-06-09T12:00:00Z
```

### Active Exploit Acknowledgement

```bash
wardex accept active-exploit --cve CVE-2024-3094 --justification "..." --art14-artefact wardex-art14-....json
```

**Exit codes (v2.0):** `0` OK · `3` Integrity failure · `10` Gate blocked · `11` Compliance fail · **`12` Actively exploited**

---
## Compliance gap analysis

Wardex compares what infosec has declared against what is operationally active, and identifies the delta against the framework.

### Input

Two YAML files with a `layer` field identifying the origin:

```yaml
# documented-controls.yaml — policies declared by infosec
- id: CTRL-IAM-001
  name: Multi-Factor Authentication
  layer: documented
  domains: [access_control]
  maturity: 4
  evidences:
    - type: policy
      ref: https://wiki.internal/sec/mfa-policy

# implemented-controls.yaml — operationally confirmed controls
# (produced by Bridgr or maintained manually)
- id: CTRL-IAM-001
  name: Multi-Factor Authentication
  layer: implemented
  domains: [access_control]
  maturity: 4
  effectiveness: 0.90
  evidences:
    - type: tool
      ref: okta-mfa-config-2026
```

The same ID appearing in both files is the expected case: a control that is both declared and confirmed operational. IDs present in only one file are the signal of interest.

### Running

```bash
wardex assess documented-controls.yaml implemented-controls.yaml \
  --framework iso27001 \
  -o markdown
```

### What the report produces

The report separates results into four compliance states:

| Category | Meaning |
|---|---|
| **Covered** | Present in `implemented` layer, maturity >= 3, with operational evidence. |
| **Policy without practice** | Documented only. No corresponding implemented control. |
| **Practice without governance** | Implemented but without a documented policy. |
| **Gap** | Absent from both layers for a catalogue control. |

The `LayerDelta` section identifies the real drift between intent (policy) and execution (code), exposing compliance illusions.

### With assets

If your asset inventory is declared, the report produces a per-asset compliance table:

```bash
wardex assess documented-controls.yaml implemented-controls.yaml \
  --assets assets.yaml \
  --framework iso27001 \
  -o json --out-file posture.json
```

```yaml
# assets.yaml — v2.0.0 Schema
- id: ASSET-PAY-001
  name: Payment API
  type: application
  criticality: 0.9
  scope: [iso27001]
  controls: [CTRL-IAM-001, CTRL-CRYPTO-002]
  exposure:
    internet_facing: true
    network_zone: dmz
    data_classification: restricted
  threats:
    - id: T-01
      scenario: "API abuse"
      likelihood: high
  owner: platform-team
```

---

## Risk-based release gate

The gate evaluates vulnerabilities using the model:

```
R(v, α) = (CVSS(v)/10) × EPSS(v) × C(α) × E(α) × (1 − Φ(α))
```

`CVSS/10` normalises the base score to [0, 1]; combined with `EPSS`, the product represents severity weighted by exploitation probability. `C` is asset criticality, `E` is effective exposure, and `Φ` is compensating control effectiveness (clamped at 0.80 — a compensating control reduces risk at most 80%). The final `R` lies in [0, 1.5]. Thresholds in `wardex-config.yaml` use the same scale.

The result is compared against the `risk_appetite` defined in `wardex-config.yaml`. Three possible outcomes: `ALLOW`, `WARN`, `BLOCK`.

### Configuration

```yaml
# wardex-config.yaml
release_gate:
  enabled: true
  risk_appetite: 0.20
  warn_above: 0.12
  mode: any               # "any" blocks if any vuln exceeds threshold; "aggregate" uses sum
  asset_context:
    criticality: 0.8
    internet_facing: true
    requires_auth: true
  compensating_controls:
    - type: waf
      effectiveness: 0.35
```

### The same CVE, four contexts

The difference between ALLOW and BLOCK is not the CVE — it is the asset context. `R` lies in [0, 1.5]; each profile carries a distinct `risk_appetite` threshold (see `data/calibration.json`).

| CVE | CVSS | EPSS | [BANK] | [SAAS] | [INFRA] | [HOSP] |
|---|---|---|---|---|---|---|
| Log4Shell | 10.0 | 0.94 | **1.41** `BLOCK` | **0.75** `BLOCK` | **1.41** `BLOCK` | **1.13** `BLOCK` |
| xz backdoor | 10.0 | 0.86 | **1.29** `BLOCK` | **0.69** `BLOCK` | **1.29** `BLOCK` | **1.03** `BLOCK` |
| curl SOCKS5 | 9.8 | 0.26 | **0.38** `BLOCK` | **0.20** `WARN` | **0.38** `BLOCK` | **0.31** `BLOCK` |
| minimist | 9.8 | 0.01 | **0.01** `ALLOW` | **0.01** `ALLOW` | **0.01** `ALLOW` | **0.01** `ALLOW` |

Calibrated against 237 real CVEs with live EPSS from FIRST.org (`data/dataset_2025-03-01.json`):

| Profile | Appetite | BLOCK | ALLOW | % Block |
|---|---|---|---|---|
| Tier-1 Bank (DORA) | 0.5 | 176 | 57 | 74% |
| Hospital (HIPAA) | 0.8 | 168 | 63 | 71% |
| SaaS Start-up | 2.0 | 111 | 86 | 47% |
| Energy/Utilities (NIS2) | 0.3 | 180 | 53 | 76% |

### EPSS enrichment

When your scanner does not include EPSS, Wardex assumes EPSS 1.0 (worst case) and blocks until explicit validation:

```bash
wardex enrich epss wardex-vulns.yaml --output epss-enrich.yaml
wardex evaluate --epss-enrichment epss-enrich.yaml --evidence vulns.yaml controls.yaml
```

Enrichment queries `api.first.org` and signs the result via HMAC-SHA256.

### Format conversion

```bash
wardex convert grype results.json > vulns.yaml
wardex convert sbom sbom.xml > vulns.yaml
```

### CI/CD integration

```yaml
# .github/workflows/wardex-gate.yml
jobs:
  risk-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Wardex
        run: go install github.com/had-nu/wardex@95eed886

      - name: Evaluate risk gate
        run: |
          wardex evaluate \
            --config .wardex/config.yaml \
            --evidence vulns.yaml \
            controls.yaml
        # Exit 0 = ALLOW, Exit 10 = BLOCK, Exit 11 = compliance gap
```

---

## Risk acceptance

When the gate blocks and there is a business case for proceeding, Wardex formalises the exception with a named owner, justification, and TTL. Silent expirations and configuration drift are detected automatically.

```bash
# Request acceptance
wardex accept request \
  --report report.json \
  --cve CVE-2024-1234 \
  --accepted-by sec-lead@company.com \
  --justification "WAF mitigates the attack vector; patch scheduled for Q3" \
  --expiry 90d

# Verify integrity of all active acceptances
wardex accept verify

# List acceptances and status
wardex accept list --active
```

Acceptances are signed with HMAC-SHA256 and recorded in an append-only log (JSONL). Wardex rejects acceptances that have expired, been tampered with, or whose `wardex-config.yaml` has drifted since signing.

---

## Governance: Trust Store & Sealed Config (WexState)

For **DORA** compliance and non-repudiable chains of custody, Wardex allows sealing risk policies (`wardex-config.yaml`) into a signed cryptographic envelope (`.wexstate`).

- **Strong identity**: Ed25519 keys for Admins, CISOs, and Analysts.
- **Sealed config**: Risk policies cannot be altered in CI/CD without executive approval.
- **Append-only trust store**: Central record of authorised keys and revocations.

```bash
# Seal the policy (CISO action)
wardex config seal --keyring ciso.wex --input config.yaml --out config.wexstate

# Evaluate with mandatory seal verification
wardex evaluate --config config.wexstate --evidence vulns.yaml --strict
```

See the [Governance Playbook](doc/operations/WARDEX_TRUST_PLAYBOOK.md) for the full workflow.

---

## SDK

```go
import "github.com/had-nu/wardex/pkg/sdk"

controls, _ := sdk.LoadControls("./controls.yaml")
result, _   := sdk.Analyze(controls, "iso27001")

fmt.Printf("Coverage: %.1f%%\n", result.Summary.GlobalCoverage)
```

For the release gate:

```go
import (
    "github.com/had-nu/wardex/pkg/model"
    "github.com/had-nu/wardex/pkg/releasegate"
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
}

report := gate.Evaluate([]model.Vulnerability{
    {CVEID: "CVE-2024-1234", CVSSBase: 9.1, EPSSScore: 0.84, Reachable: true},
})

fmt.Println(report.OverallDecision) // ALLOW | WARN | BLOCK
```

---

## Documentation

- [Architecture and internals](doc/architecture/TECHNICAL_VIEW.md)
- [Business context and the binary gate problem](doc/architecture/BUSINESS_VIEW.md)
- [Playbook — use cases with full commands](doc/operations/WARDEX_PLAYBOOK.md)
- [Governance — Trust Store & Sealed Config Playbook](doc/operations/WARDEX_TRUST_PLAYBOOK.md)
- [GitHub Actions integration](doc/operations/github-actions-integration.md)
- [Exit codes](doc/operations/EXIT_CODES.md)
- [CHANGELOG](CHANGELOG.md)

---

## Licensing

Dual-licensed:

**AGPL-3.0 (free):** use in internal CI/CD pipelines or in open-source projects that make their source available.

**Commercial licence (paid):** embedding in proprietary products, SaaS platforms, or distribution without opening source. See the [Commercial Terms](doc/governance/COMMERCIAL_LICENSE.md) or contact **andre_ataide@proton.me**.
