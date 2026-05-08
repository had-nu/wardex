<div align="center">

![Wardex Lockup](pkg/ui/wardex-lockup.svg)

[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/)
[![Go Report Card](https://goreportcard.com/badge/github.com/had-nu/wardex?style=flat-square)](https://goreportcard.com/report/github.com/had-nu/wardex)
[![CI](https://github.com/had-nu/wardex/actions/workflows/ci.yml/badge.svg)](https://github.com/had-nu/wardex/actions/workflows/ci.yml)
[![License: AGPL v3 / Commercial](https://img.shields.io/badge/License-AGPL_v3_%7C_Commercial-8A2BE2.svg?style=flat-square)](#licensing)

<br>
<a href="README-en.md">English</a> | <a href="README.md">Português</a>
<br><br>

</div>

> [!IMPORTANT]
> **Supply chain hardening (TeamPCP):** Following the TeamPCP campaign — which turned security tooling into attack vectors against CI/CD pipelines — Wardex accelerated its defensive hardening roadmap. GitHub Actions use SHA256 pinning, workflows declare minimal permissions explicitly, and EPSS enrichment payloads are cryptographically signed before entering the pipeline.

---

**Wardex** is a CLI and Go library with two distinct purposes:

1. **Risk-based release gate** — evaluates vulnerabilities in asset context (CVSS × EPSS × criticality × exposure × compensating controls) and decides ALLOW, WARN, or BLOCK. Replaces static CVSS thresholds.

2. **Compliance gap analysis** — compares controls documented by infosec against operationally confirmed controls, and maps both against a framework catalogue. Identifies real coverage, what exists only on paper (*paper security*), and what operates without a policy (*shadow security*).

The two modes are independent. You can use either one on its own.

---

## Supported frameworks

ISO/IEC 27001:2022 · SOC 2 · NIS 2 · DORA

```bash
wardex assess controls.yaml --framework iso27001  # default
wardex assess controls.yaml --framework nis2
wardex assess controls.yaml --framework dora
```

---

## Installation

```bash
go install github.com/had-nu/wardex@v1.9.0
```

Requires Go ≥ 1.26. Ensure `$(go env GOPATH)/bin` is in your `$PATH`.

To build from source:

```bash
git clone https://github.com/had-nu/wardex.git
cd wardex && make build
```

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
| **Paper security** | Documented only. No corresponding implemented control. (Policy Gap) |
| **Shadow security** | Implemented but without a documented policy. |
| **Gap** | Absent from both layers for a catalogue control. |

The `LayerDelta` section identifies the real drift between intent (policy) and execution (code), exposing "compliance illusions".

### With assets

If your asset inventory is declared, the report produces a per-asset compliance table:

```bash
wardex assess documented-controls.yaml implemented-controls.yaml \
  --assets assets.yaml \
  --framework iso27001 \
  -o json --out-file posture.json
```

```yaml
# assets.yaml — v1.8.0 Schema
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

CVSS is divided by 10 to normalise the scale: the product `(CVSS/10) × EPSS` lies in [0, 1], and the final output `R` in [0, 1.5]. Thresholds in `wardex-config.yaml` (`risk_appetite`, `warn_above`) are expressed on this same scale.

`C` is asset criticality, `E` is effective exposure, and `Φ` is compensating control effectiveness (clamped at 0.80 — maximum 80% reduction, `1 − Φ` minimum 0.20).

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

The difference between ALLOW and BLOCK is not the CVE — it is the asset context.

| CVE | CVSS | EPSS | [BANK] | [SAAS] | [INFRA] | [HOSP] |
|---|---|---|---|---|---|---|
| Log4Shell | 10.0 | 0.94 | **1.41** `BLOCK` | **0.75** `BLOCK` | **1.41** `BLOCK` | **1.13** `BLOCK` |
| xz backdoor | 10.0 | 0.86 | **1.29** `BLOCK` | **0.69** `BLOCK` | **1.29** `BLOCK` | **1.03** `BLOCK` |
| curl SOCKS5 | 9.8 | 0.26 | **0.38** `BLOCK` | **0.20** `WARN` | **0.38** `BLOCK` | **0.31** `BLOCK` |
| minimist | 9.8 | 0.01 | **0.01** `ALLOW` | **0.01** `ALLOW` | **0.01** `ALLOW` | **0.01** `ALLOW` |

*R ∈ [0, 1.5]. Per-profile thresholds on the normalised scale — see `data/calibration.json`.*

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
        run: go install github.com/had-nu/wardex@v1.9.0

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

*   **Strong Identity**: Based on Ed25519 keys for Admins, CISOs, and Analysts.
*   **Sealed Config**: Prevents risk policies from being altered in CI/CD without executive approval.
*   **Append-Only Trust Store**: Central record of authorized keys and revocations.

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

**Commercial licence (paid):** embedding in proprietary products, SaaS platforms, or distribution without opening source. See the [Commercial Terms](doc/COMMERCIAL_LICENSE.md) or contact **andre_ataide@proton.me**.
