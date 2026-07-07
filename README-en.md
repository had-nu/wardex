<h1 align="center">Wardex — The CRA-Ready Release Gate for NIS2 &amp; DORA</h1>

<div align="center">

![Wardex Lockup](pkg/ui/wardex-lockup.svg)

[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/)
[![Go Report Card](https://goreportcard.com/badge/github.com/had-nu/wardex?style=flat-square)](https://goreportcard.com/report/github.com/had-nu/wardex)
[![Coverage](https://img.shields.io/badge/coverage-40%25-yellow?style=flat-square)](#)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io/had--nu/wardex-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/had-nu/wardex/pkgs/container/wardex)
[![Helm](https://img.shields.io/badge/Helm-v0.1.0-0F1689?style=flat-square&logo=helm&logoColor=white)](deploy/helm/wardex/)
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

**European positioning:** Wardex is built from the ground up for European regulations — NIS2, DORA, CRA — and for the compliance standard emerging across the EU. Every release gate decision, every risk acceptance, every Art14 artefact is cryptographically sealed and recorded in a chained audit log that survives external audits.

---

## Chained Audit Log — Core Feature

The chained audit log is the heart of Wardex. Each entry is cryptographically linked to the previous one, forming an unbreakable chain of evidence.

```
┌─────────────┐    SHA-256    ┌─────────────┐    SHA-256    ┌─────────────┐
│  Entry 1    │──────────────▶│  Entry 2    │──────────────▶│  Entry 3    │
│  (genesis)  │               │  (decision) │               │  (acceptance)│
└─────────────┘               └─────────────┘               └─────────────┘
       │                             │                             │
       ▼                             ▼                             ▼
  Config hash                 Config hash                   Config hash
  (CPL v2.2)                  (CPL v2.2)                   (CPL v2.2)
```

**What makes it tamper-proof:**
- Each entry includes the hash of the previous entry (chained hashing)
- The config hash (CPL) links every decision to the policy in effect
- Any modification to the audit log or config is immediately detectable
- Exportable as JSONL for SIEM, Datadog, or external audit

```bash
# Verify chain integrity
wardex audit verify-chain --audit-log wardex-gate-audit.log

# Verify linkage with archived configurations
wardex audit verify-link --audit-log wardex-gate-audit.log --config-archive ./configs/
```

---

## What's New — v2.2.2

**Security Hardening:**
- Workspace confinement: `evaluate` restricts file access to the project root
- Pathguard: replaces ad-hoc SafePath with validated path checking
- SBOM generation with pinned syft and SHA-256 verification

**Code Quality (PR #102):**
- Consolidated atomic writes (`pkg/atomicwrite`) — fixed temp-file leak
- Shared gate pipeline (`pkg/gate`) — DRY between evaluate and wardex commands
- `runEvaluate()` decomposed from CC=123 into 11 focused helpers

**Immutable Provenance (v2.3.0 branch):**
- Cryptographic provenance manifest with BLAKE3 + Ed25519
- Bitcoin anchoring via OpenTimestamps
- Ethereum/Polygon anchoring via `ProvenanceAnchor` smart contract

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
go install github.com/had-nu/wardex/v2@latest
```

Requires Go ≥ 1.26. Ensure `$(go env GOPATH)/bin` is in your `$PATH`.

To build from source:

```bash
git clone https://github.com/had-nu/wardex.git
cd wardex && make build
```

### Docker

```bash
docker pull ghcr.io/had-nu/wardex:2.2.2
```

### Helm (Kubernetes)

```bash
helm upgrade --install wardex deploy/helm/wardex/ \
  --set acceptSecret.value=$(openssl rand -hex 32)
```

See [deploy/helm/wardex/](deploy/helm/wardex/) for the full chart reference.

---

## Quickstart

### 1. Evaluate vulnerability risk

```bash
# Convert Grype output to Wardex format
wardex convert grype test/usability/grype-results.json > vulns.yaml

# Evaluate with asset context
wardex evaluate \
  --evidence vulns.yaml \
  --config doc/examples/wardex-config.yaml

# Dry-run — preview without writing artefacts
wardex evaluate --evidence vulns.yaml --config doc/examples/wardex-config.yaml --dry-run
```

### 2. Generate and manage keys

```bash
# Generate Ed25519 keypair for the trust system
wardex keygen

# Key is created at ~/.crypto/trust/root.key
# Public key is ~/.crypto/trust/root.key.pub (send to admin)
```

### 3. Seal and verify provenance

```bash
# Seal source tree (from v2.3.0 branch)
immutable-provenance seal \
  --dir . \
  --output provenance.yaml \
  --version v2.2.2 \
  --keyring ~/.crypto/provenance/signing.key

# Verify integrity
immutable-provenance verify --manifest provenance.yaml --dir .
```

**Exit codes:** `0` ALLOW · `3` Tampered · `4` Store inconsistent · `10` BLOCK · `11` Gap · `12` Actively exploited

---

## Command Reference

| Command | Description |
|---------|-------------|
| `wardex evaluate` | Evaluate vulnerabilities against the release gate |
| `wardex assess` | Compliance gap analysis |
| `wardex convert grype/sbom` | Convert scanner output to Wardex format |
| `wardex enrich epss` | Enrich vulnerabilities with EPSS data |
| `wardex accept request/verify/list` | Risk acceptance management |
| `wardex art14 list/show/verify` | CRA Article 14 artefact lifecycle |
| `wardex config hash/seal` | CPL and sealed config |
| `wardex audit verify-chain/verify-link` | Chained audit log verification |
| `wardex trust init/add` | Trust store management |
| `wardex keygen` | Ed25519 keypair generation |
| `wardex pki init/issue` | PKI mode with Ed25519 CA |
| `wardex policy show` | Show configured risk policy |
| `wardex simulate` | Simulate gate decisions with historical data |

---

## Risk-Based Release Gate

The gate evaluates each vulnerability with the model:

```
R(v, α) = (CVSS(v)/10) × EPSS(v) × C(α) × E(α) × (1 − Φ(α))
```

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

| CVE | CVSS | EPSS | [BANK] | [SAAS] | [INFRA] | [HOSP] |
|---|---|---|---|---|---|---|
| Log4Shell | 10.0 | 0.94 | **1.41** `BLOCK` | **0.75** `BLOCK` | **1.41** `BLOCK` | **1.13** `BLOCK` |
| xz backdoor | 10.0 | 0.86 | **1.29** `BLOCK` | **0.69** `BLOCK` | **1.29** `BLOCK` | **1.03** `BLOCK` |
| curl SOCKS5 | 9.8 | 0.26 | **0.38** `BLOCK` | **0.20** `WARN` | **0.38** `BLOCK` | **0.31** `BLOCK` |
| minimist | 9.8 | 0.01 | **0.01** `ALLOW` | **0.01** `ALLOW` | **0.01** `ALLOW` | **0.01** `ALLOW` |

### EPSS enrichment

```bash
wardex enrich epss wardex-vulns.yaml --output epss-enrich.yaml
wardex evaluate --epss-enrichment epss-enrich.yaml --evidence vulns.yaml controls.yaml
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
        run: go install github.com/had-nu/wardex/v2@latest
      - name: Evaluate risk gate
        run: |
          wardex evaluate \
            --config .wardex/config.yaml \
            --evidence vulns.yaml \
            controls.yaml
```

---

## Compliance Gap Analysis

Wardex compares what infosec has declared against what is operationally active, and identifies the delta against the framework.

| Category | Meaning |
|---|---|
| **Covered** | Present in `implemented` layer, maturity >= 3, with operational evidence. |
| **Policy without practice** | Documented only. No corresponding implemented control. |
| **Practice without governance** | Implemented but without a documented policy. |
| **Gap** | Absent from both layers for a catalogue control. |

```bash
wardex assess documented-controls.yaml implemented-controls.yaml \
  --framework iso27001 \
  -o markdown

# With asset inventory
wardex assess documented-controls.yaml implemented-controls.yaml \
  --assets assets.yaml \
  --framework iso27001 \
  -o json --out-file posture.json
```

---

## CRA Article 14

The EU Cyber Resilience Act's active exploitation notification obligations enter into force in September 2026.

**Active Exploitation Hard Stop:** When a vulnerability is classified as actively exploited (`actively_exploited: true`), `wardex evaluate` exits with code **12** — distinct from the normal gate block (10). It cannot be overridden by risk acceptances.

```bash
# Art14 artefact
wardex art14 list
wardex art14 show <artefact-id>
wardex art14 verify <artefact-id>
wardex art14 mark-dispatched <artefact-id> --phase early-warning

# Active exploit acceptance
wardex accept active-exploit --cve CVE-2024-3094 --justification "..." --art14-artefact wardex-art14-....json
```

See the [Governance Playbook](doc/operations/WARDEX_TRUST_PLAYBOOK.md) for the full workflow.

---

## Key Management & Governance

### Cryptographic Keys

All Ed25519 keys are stored in `~/.crypto/` with subdirectories by purpose:

```
~/.crypto/
├── provenance/          # Provenance manifest signing
│   ├── signing.key      # Ed25519 private (mode 0400)
│   └── signing.key.pub  # Ed25519 public
└── trust/               # Wardex trust system
    └── root.key         # Root key (generated by wardex keygen)
```

**Permissions**: Directories `700`, private keys `0400`, public keys `0644`.

### Trust Store & Sealed Config (WexState)

For **DORA** compliance and non-repudiable chains of custody:

- **Strong identity**: Ed25519 keys for Admins, CISOs, and Analysts.
- **Sealed config**: Risk policies cannot be altered without executive approval.
- **Append-only trust store**: Central record of authorised keys and revocations.

```bash
# Seal the policy (CISO action)
wardex config seal --keyring ~/.crypto/trust/root.key --input config.yaml --out config.wexstate

# Evaluate with mandatory seal verification
wardex evaluate --config config.wexstate --evidence vulns.yaml --strict
```

### PKI Mode

For environments that require certificate-based identity:

```bash
wardex pki init --org "Your Corp" --validity 3650d
wardex pki issue --name ci-agent --out ci-agent.wex
wardex config seal --keyring ci-agent.wex --input config.yaml --out config.wexstate
```

---

## Environment & Syslog

| Variable | Default | Description |
|---|---|---|
| `WARDEX_ACCEPT_SECRET` | — | HMAC-SHA256 key for signing acceptances and Art14 artefacts (min 32 chars) |
| `WARDEX_ACTOR` | `cli` | Identity string recorded in audit entries |
| `WARDEX_SYSLOG_ENDPOINT` | — | `tcp://syslog.example.com:514` — forward audit events to central syslog |
| `WARDEX_SYSLOG_PROTO` | `tcp` | Syslog transport: `tcp`, `udp`, or `tls` |
| `WARDEX_SYSLOG_CERT` | — | TLS client cert path for `tls` proto |
| `WARDEX_SYSLOG_KEY` | — | TLS client key path for `tls` proto |
| `WARDEX_SYSLOG_CA` | — | Custom CA cert path for `tls` proto |

---

## SDK

```go
import "github.com/had-nu/wardex/v2/pkg/sdk"

controls, _ := sdk.LoadControls("./controls.yaml")
result, _   := sdk.Analyze(controls, "iso27001")

fmt.Printf("Coverage: %.1f%%\n", result.Summary.GlobalCoverage)
```

For the release gate:

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
- [Helm chart reference](deploy/helm/wardex/)
- [Exit codes](doc/operations/EXIT_CODES.md)
- [Dev environment (docker-compose)](docker-compose.yml)
- [CHANGELOG](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)

---

## Licensing

Dual-licensed:

**AGPL-3.0 (free):** use in internal CI/CD pipelines or in open-source projects that make their source available.

**Commercial licence (paid):** embedding in proprietary products, SaaS platforms, or distribution without opening source. See the [Commercial Terms](doc/governance/COMMERCIAL_LICENSE.md) or contact **andre_ataide@proton.me**.
