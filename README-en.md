<div align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="pkg/ui/wardex-shield-dark.png">
  <img src="pkg/ui/wardex-shield.png" alt="Wardex symbol" width="256">
</picture>

<h1>WARDEX</h1>
<p><strong>Auditable security and compliance decisions</strong></p>
<p><em>Risk-based release governance for NIS2 · DORA · CRA · EU AI Act</em></p>

[![Go](https://img.shields.io/badge/Go-1.27-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/)
[![Go Report Card](https://goreportcard.com/badge/github.com/had-nu/wardex?style=flat-square)](https://goreportcard.com/report/github.com/had-nu/wardex)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io/had--nu/wardex-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/had-nu/wardex/pkgs/container/wardex)
[![Helm](https://img.shields.io/badge/Helm-v0.1.0-0F1689?style=flat-square&logo=helm&logoColor=white)](deploy/helm/wardex/)
[![GitHub Action](https://img.shields.io/badge/GitHub_Action-Wardex_Release_Gate-4A154B?style=flat-square&logo=githubactions&logoColor=white)](https://github.com/marketplace/actions/wardex-release-gate)
[![License: AGPL v3 / Commercial](https://img.shields.io/badge/License-AGPL_v3_%7C_Commercial-8A2BE2.svg?style=flat-square)](#licensing)

<br>
<a href="README-en.md">English</a> | <a href="README.md">Português</a>
<br><br>

</div>

> **Current release:** `v2.6.0` · Go `1.27` · configuration schema `2`

> [!IMPORTANT]
> **CRA Article 14 (available since v2.0; maintained in v2.6.0):** The Cyber Resilience Act's active exploitation notification obligations enter into force in September 2026. The current path correlates the CISA KEV catalogue, uses exit code `12`, signs the artefact with HMAC-SHA256, and records the three regulatory deadlines. This path cannot be overridden by risk acceptances.
>
> **EU AI Act (available since v2.4.0; included in v2.6.0):** The Artificial Intelligence Regulation (EU 2024/1689) is available as a controls framework. Its 31 catalogued controls cover prohibited practices, risk management, data governance, transparency, human oversight, accuracy/robustness/cybersecurity, provider and deployer obligations, GPAI, post-market monitoring, and incident reporting. Use `--framework eu_ai_act` to assess compliance.

---

Wardex is a CLI and Go library that turns security and compliance decisions into auditable evidence. Two independent modes — neither requires the other.

**European positioning:** Wardex is built from the ground up for European regulations — NIS2, DORA, CRA, **EU AI Act** — and for the compliance standard emerging across the EU. Every release gate decision, every risk acceptance, every Art14 artefact is cryptographically sealed and recorded in a chained audit log that survives external audits.

**Visual identity:** the promise, design tokens, and brand variants are documented in [BRANDING.md](doc/architecture/BRANDING.md).

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
  (CPL schema v2)                  (CPL schema v2)                   (CPL schema v2)
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

# Paginated SIEM export
wardex audit export --audit-log wardex-gate-audit.log --format jsonl --limit 500
```

---

## What's New — v2.6.0 (2026-09-15)

The current line is **v2.6.0** and remains compatible with legacy formats.

**CPL chain and provenance (P0/L1/L4/L5):**
- Explicit `config_schema_version: 2` and `cpl_schema_version`; the chain uses
  canonical `previous_entry_hash`, and `wardex audit verify-chain` streams.
- `wardex audit export --limit N [--cursor <sha256>] [--tail]` exports JSONL/CSV
  for SIEM consumption with cursor pagination and metadata.
- `wardex gate check-version --audit-log ... --version 2.6.0` prevents sealing
  the same version twice (`13 = DuplicateRelease`). In release-seal mode,
  `--release-version` requires `--policy-ref`.

**Gate and evidence (L3/L7):**
- `--gate-class pr|deploy|nightly` with `block|advisory|off` severities;
  advisory-only freshness returns `6 = FreshnessAdvisory`.
- `release_gate.forced_upgrade.{enabled,deadline,tripwire_failures}` and the
  `--forced-upgrade` / `--forced-upgrade-state` flags activate the evidence
  tripwire. State is stored in `.wardex/forced_upgrade.json`.

**Keys and Article 14 (L2/L6):**
- `wardex keygen --encrypt` creates `WARDEX-KEY-V1` envelopes (Argon2id +
  AES-256-GCM); pass the passphrase with `--passphrase` or
  `WARDEX_KEY_PASSPHRASE`. Legacy plaintext keyrings remain valid.
- Article 14 artefacts carry `format_version` and `capabilities`; future
  versions are rejected without a silent downgrade. Schemas live in
  `spec/cddl/`.

**Terminal UI (current main):**
- TTY dashboards for evaluation, governance, and verification commands;
  JSON/CSV/pipes/CI remain machine-oriented and undecorated.
- `NO_COLOR`, `TERM=dumb`, `COLUMNS`, `CI`, `GITHUB_ACTIONS`, and `GITLAB_CI`
  control the fallback. See
  [`doc/architecture/TERMINAL_UI.md`](doc/architecture/TERMINAL_UI.md).

**New exit codes:** `6 = FreshnessAdvisory` and `13 = DuplicateRelease`.

> Design patterns in this release are inspired by the Nym ecosystem (Apache-2.0) —
> used as a reference, with no code copied. See [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md).

---

## Historical foundation — v2.4.0

**EU AI Act Framework (31 controls):**
- Complete catalogue of Regulation (EU) 2024/1689: prohibited practices, risk management, data governance, technical documentation, transparency, human oversight, accuracy/robustness/cybersecurity, provider and deployer obligations, fundamental rights impact assessment, GPAI, post-market monitoring, incident reporting
- Usage: `wardex --framework eu_ai_act ./frameworks/eu_ai_act/*.yml`

**Gleipnir Provenance Anchoring:**
- Immutable integrity proof for release artifacts via `wardex provenance seal`
- Supports embedded consensus engine (gleipnir-embedded) or remote gRPC server
- Chain seal with SHA-256 of all artifacts + cryptographic anchor

**gRPC driver isolation:**
- The gRPC provenance driver (with protobuf) is now behind the `grpc` build tag to prevent init panic. To use: `go build -tags grpc`.

---

## Frameworks and workflows

**Selectable frameworks:** ISO/IEC 27001:2022 · SOC 2 · NIS 2 · DORA · NIST CSF 2.0 · **EU AI Act**

**Regulatory workflows:** CRA Article 14, risk acceptances, provenance, chained audit logs, and release governance.

```bash
wardex assess controls.yaml --framework iso27001     # default
wardex assess controls.yaml --framework nis2
wardex assess controls.yaml --framework dora
wardex assess controls.yaml --framework eu_ai_act
```

---

## Installation

```bash
# Current release
go install github.com/had-nu/wardex/v2@v2.6.0

# Latest published tag
go install github.com/had-nu/wardex/v2@latest
```

Requires Go ≥ 1.27. Ensure `$(go env GOPATH)/bin` is in your `$PATH`.

To build from source:

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

See [deploy/helm/wardex/](deploy/helm/wardex/) for the full chart reference. Chart `0.1.0` uses application `v2.6.0`.

---

## Quickstart

### 1. Evaluate vulnerability risk

```bash
# Convert Grype output to Wardex format
wardex convert grype test/usability/grype-results.json > vulns.yaml

# Evaluate with asset context
wardex evaluate \
  --evidence vulns.yaml \
  --config doc/examples/wardex-config.yaml \
  test/testdata/documented-controls.yaml

# Dry-run — preview without writing artefacts
wardex evaluate --evidence vulns.yaml --config doc/examples/wardex-config.yaml \
  test/testdata/documented-controls.yaml --dry-run
```

### 2. Generate and manage keys

```bash
# Generate an Ed25519 keypair for the trust system
wardex keygen

# Optional: use instead of `keygen` to create an encrypted envelope
WARDEX_KEY_PASSPHRASE="$(openssl rand -base64 32)" wardex keygen --encrypt

# Key is created at ~/.crypto/trust/root.key
# Public key is ~/.crypto/trust/root.key.pub (send to admin)
```

### 3. Seal and verify provenance

```bash
# Seal artifact directory with Gleipnir (v2.6.0; compatible with v2.4.0+)
wardex provenance seal \
  --dir ./dist \
  --output chain-seal.json \
  --label "release-v2.6.0"

# Verify integrity
wardex provenance verify <chain-hash>
```

**Exit codes:** `0` OK · `1` generic error · `3` integrity failure · `4` store inconsistent · `5` expiring soon · `6` freshness advisory · `10` BLOCK · `11` compliance failure · `12` active exploitation · `13` duplicate release

---

## Terminal UI

When the destination is an interactive terminal, the evaluation commands, `art14`, `simulate`, `keygen`, `config`, `provenance`, `chain`, `hmac`, `audit`, `enrich`, `convert`, `assets`, `auth`, `contract`, `policy`, `state`, `gate`, `accept`, and `trust` render a text dashboard with:

- product header and version;
- effective session parameters;
- real pipeline phases (`RUNNING`, `DONE`, `SKIPPED`, `FAILED`);
- focused compliance-gap or release-gate decision cards;
- coverage, severity, and release-gate summary.

JSON, CSV, pipes, files, and CI output remain clean and undecorated. Sensitive fields are displayed as `[REDACTED]`. `audit export` remains machine-oriented and streaming to preserve JSONL/CSV and pagination metadata.

Environment controls:

- `NO_COLOR` — disable colours;
- `TERM=dumb` — use the ASCII fallback;
- `COLUMNS` — provide an alternative terminal width;
- `CI`, `GITHUB_ACTIONS`, and `GITLAB_CI` — disable decorative output.

See [`doc/architecture/TERMINAL_UI.md`](doc/architecture/TERMINAL_UI.md) for the complete layout specification.

---

## Command Reference

The root command `wardex <inputs>` runs gap analysis; the subcommands below
provide focused gate, governance, evidence, and verification operations.

| Command | Description |
|---------|-------------|
| `wardex` | Gap analysis against a framework, with an optional release gate |
| `wardex assess` | Compliance assessment with asset inventory and layer delta |
| `wardex evaluate` | Release gate over a vulnerability evidence file |
| `wardex aggregate` | Aggregate gate results into one decision |
| `wardex convert grype/sbom/kev` | Convert third-party output to Wardex format |
| `wardex enrich epss` | Fetch and sign missing EPSS scores |
| `wardex accept` | Request, revoke, expiry, verify, and active-exploit acceptance workflows |
| `wardex auth status/verify` | Trust-store status and actor permissions |
| `wardex contract verify` | SHA-256 contract integrity verification |
| `wardex policy` | `validate`, `list`, `add`, and `check-expiry` |
| `wardex state` | Persistent `status`, `history`, `trend`, `dashboard`, `verify`, and `cleanup` |
| `wardex gate check-version` | Duplicate-release guard; returns `13` for duplicates |
| `wardex art14` | `list`, `show`, `mark-dispatched`, `finalize`, and `verify` |
| `wardex provenance` | `seal`, `submit`, `attest`, `verify`, and `status` via 3CP |
| `wardex config` | Configuration `hash`, `seal`, and `show` |
| `wardex audit` | `verify-chain`, `verify-link`, and cursor-based SIEM `export` |
| `wardex trust` | `init`, `add`, `revoke`, `list`, `show`, and `verify` |
| `wardex keygen` | Ed25519 keypair generation, with optional `--encrypt` |
| `wardex chain seal` | SHA-256 seal for artifacts |
| `wardex hmac sign` | HMAC-SHA256 file signatures |
| `wardex assets inventory` | ICT asset inventory |
| `wardex simulate` | Interactive decision simulator |

The shell also provides `wardex completion` for command completion.

---

## Risk-Based Release Gate

### Configuration

```yaml
# wardex-config.yaml
config_schema_version: 2
release_gate:
  enabled: true
  risk_appetite: 0.20
  warn_above: 0.12
  mode: any               # "any" blocks per vulnerability; "aggregate" uses the sum
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

### The same CVE, four contexts

Risk heatmap: each cell shows the **risk score** (context exposure × EPSS) and the **gate decision** for the same CVEs in four contexts. The hotter the colour, the higher the score.

| CVE | CVSS | EPSS | [BANK] | [SAAS] | [INFRA] | [HOSP] |
|---|---|---|---|---|---|---|
| Log4Shell | 10.0 | 0.94 | 🟥 **1.41 BLOCK** | 🟧 **0.75 BLOCK** | 🟥 **1.41 BLOCK** | 🟥 **1.13 BLOCK** |
| xz backdoor | 10.0 | 0.86 | 🟥 **1.29 BLOCK** | 🟧 **0.69 BLOCK** | 🟥 **1.29 BLOCK** | 🟥 **1.03 BLOCK** |
| curl SOCKS5 | 9.8 | 0.26 | 🟨 **0.38 BLOCK** | 🟨 **0.20 WARN** | 🟨 **0.38 BLOCK** | 🟨 **0.31 BLOCK** |
| minimist | 9.8 | 0.01 | 🟩 **0.01 ALLOW** | 🟩 **0.01 ALLOW** | 🟩 **0.01 ALLOW** | 🟩 **0.01 ALLOW** |

**Legend (score intensity):** 🟩 < 0.20 · 🟨 0.20–0.49 · 🟧 0.50–0.99 · 🟥 ≥ 1.00

> There is no one-size-fits-all release decision: Log4Shell and the xz backdoor block in **every** context (high score under any exposure); curl SOCKS5 (EPSS 0.26) is **WARN at the risk-appetite edge on SaaS** (0.20) but **BLOCK** in banking/infra contexts; minimist is residual and passes everywhere. The heatmap shows how the same CVE aggregates different risk depending on exposure — which is why the gate is evaluated **per context**, not as "one decision for all".

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

## EU AI Act (Artificial Intelligence Regulation)

Regulation (EU) 2024/1689 — the EU AI Act — is available as a controls framework since v2.4.0 and is included in the current v2.6.0 CLI. Its 31 catalogued controls cover obligations applicable to high-risk AI systems, general-purpose AI models (GPAI), and prohibited practices.

### Controls by domain

| Domain | Controls | Articles |
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
# Assess compliance with EU AI Act
wardex --framework eu_ai_act ./frameworks/eu_ai_act/*.yml

# List catalogue controls
wardex --framework eu_ai_act --output json ./frameworks/eu_ai_act/*.yml
```

### Provenance with Gleipnir

Each release can be cryptographically sealed with the Gleipnir embedded consensus engine:

```bash
# Seal release artifacts
wardex provenance seal \
  --dir ./dist \
  --output chain-seal.json \
  --label "wardex-v2.6.0"

# Anchor a tag commit
wardex provenance submit $(git rev-parse v2.6.0) --label "git-tag-v2.6.0"

# Check chain status
wardex provenance status
```

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

### Provenance Verification

For the current v2.6.0 line, use the embedded Gleipnir engine:

```bash
# Verify a release chain seal
wardex provenance verify <chain-hash>

# Check chain status
wardex provenance status
```

For legacy releases (v2.2.2 and earlier), the public key below verifies the provenance manifest:

> **Signing public key (v2.2.2):**
> ```
> ed25519:HsD9e6BB2LlaeKODGqgWUZoflDgdUH1HWTdyWA7dGqE=
> ```

> **Root hash (BLAKE3, 113 files):**
> ```
> sha256:6f972edf99f5457f8fb13668c529f4343dab7a76d20b67ea746ebdf54d910fee
> ```

```bash
# Download the signed manifest from the release
gh release download v2.2.2 --pattern "provenance-manifest*"

# Verify (requires immutable-provenance binary from v2.3.0 branch)
immutable-provenance verify \
  --manifest provenance-manifest-v2.2.2-signed.yaml \
  --dir /path/to/wardex-v2.2.2
```

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

---

## Environment

| Variable | Default | Description |
|---|---|---|
| `WARDEX_ACCEPT_SECRET` | — | HMAC-SHA256 secret for acceptance and Art14 signatures (minimum 32 characters) |
| `WARDEX_ACTOR` | `USER` | Identity recorded in audit entries; `GITHUB_ACTOR` takes precedence when set |
| `WARDEX_KEY_PASSPHRASE` | — | Passphrase for `WARDEX-KEY-V1` envelopes |
| `WARDEX_TRUST_STORE` | `./wardex-trust.yaml` | Trust-store reference |
| `WARDEX_RELEASE_VERSION` | — | Release-seal version; can also be supplied with `--release-version` |
| `WARDEX_POLICY_REF` | — | Policy reference required with `WARDEX_RELEASE_VERSION` |

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
    Mode:         "any",
}

report := gate.Evaluate([]model.Vulnerability{
    {CVEID: "CVE-2024-1234", CVSSBase: 9.1, EPSSScore: 0.84, Reachable: true},
})

fmt.Println(report.OverallDecision) // ALLOW | WARN | BLOCK
```

---

## Documentation

- [Visual identity and branding](doc/architecture/BRANDING.md)
- [Terminal UI](doc/architecture/TERMINAL_UI.md)
- [Architecture and internals](doc/architecture/TECHNICAL_VIEW.md)
- [Business context and the binary gate problem](doc/architecture/BUSINESS_VIEW.md)
- [Playbook — use cases with full commands](doc/operations/WARDEX_PLAYBOOK.md)
- [Governance — Trust Store & Sealed Config Playbook](doc/operations/WARDEX_TRUST_PLAYBOOK.md)
- [GitHub Actions integration](doc/operations/github-actions-integration.md)
- [Helm chart reference](deploy/helm/wardex/)
- [Exit codes](doc/operations/EXIT_CODES.md)
- [Dev environment (docker-compose)](docker-compose.yml)
- [CHANGELOG](CHANGELOG.md)
- [v2.6.0 release notes](doc/releases/v2.6.0-notes.md)
- [Contributing](CONTRIBUTING.md)

---

## Licensing

Dual-licensed:

**AGPL-3.0 (free):** use in internal CI/CD pipelines or in open-source projects that make their source available.

**Commercial licence (paid):** embedding in proprietary products, SaaS platforms, or distribution without opening source. See the [Commercial Terms](doc/governance/COMMERCIAL_LICENSE.md) or contact **andre_ataide@proton.me**.

**Attributions / Provenance:** some features follow design patterns from the Nym ecosystem (Apache-2.0), as a reference and with no code copied. See [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md).
