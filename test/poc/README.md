# Wardex PoC — Risk-Based Release Gate Validation

End-to-end validation of the [Wardex](https://github.com/had-nu/wardex) library
as a CI/CD release gate. Covers four critical scenarios across the Go SDK and the CLI.

---

## Directory Structure

```
test/poc/
├── main.go                              # Go SDK integration test (4 scenarios)
├── run-all-scenarios.sh                 # Local CLI runner (no CI needed)
├── wardex-config.yaml                   # Risk appetite & gate policy
├── controls.yaml                        # Org ISO 27001 control inventory
├── scenario-01-happy-path.yaml          # ALLOW — low-risk vulns
├── scenario-02-block-critical.yaml      # BLOCK — critical RCE
├── scenario-03-compensating-controls.yaml  # ALLOW — controls dampen risk
├── scenario-04-risk-acceptance.yaml     # BLOCK → exception → ALLOW
├── wardex-gate.yml                      # GitHub Actions pipeline template
└── README.md                           # This file
```

---

## Scenarios

| # | Name | Key Input | Expected | Composite Risk |
|---|------|-----------|----------|----------------|
| 01 | Happy Path | CVSS 3.2, EPSS 0.018, no reach | **ALLOW** | ~0.000 |
| 02 | Critical Block | CVSS 9.8, EPSS 0.91, internet, no auth | **BLOCK** | ~1.34 |
| 03 | Compensating Controls | CVSS 8.1 + WAF + auth + segmentation | **ALLOW** | ~0.04 |
| 04 | Risk Acceptance | CVSS 9.1, no controls, no auth → exception | **BLOCK** (baseline) | ~1.16 |

---

## Prerequisites

- **Go >= 1.22** installed
- **WARDEX_HMAC_SECRET** environment variable set (for Scenario 04 acceptance flow)
- Repository cloned locally

---

## How to Run

### Option A: SDK Integration Test Only

This runs the Go SDK test (`main.go`) which validates the 4 scenarios directly
using the `releasegate.Gate.Evaluate()` API — no CLI binary required.

```bash
cd test/poc
go run main.go
```

**Expected output:**
```
╔══════════════════════════════════════════════════╗
║     Wardex SDK PoC — Scenario Validation         ║
╚══════════════════════════════════════════════════╝

[PASS] [PASS] 01 · Happy Path → ALLOW
      Gate decision : allow

[PASS] [PASS] 02 · Critical CVE → BLOCK
      Gate decision : block

[PASS] [PASS] 03 · Compensating Controls → ALLOW
      Gate decision : allow

[PASS] [PASS] 04 · Risk Acceptance baseline → BLOCK (pre-exception)
      Gate decision : block

─────────────────────────────────────────────────────
Results: 4 passed / 0 failed
[PASS] All scenarios passed — wardex library behaves as expected.
```

### Option B: Full CLI + SDK End-to-End (with Risk Acceptance)

This runs all 4 scenarios via the Wardex CLI binary **plus** the SDK test, including
the full risk acceptance flow (request → verify → re-evaluate).

```bash
# 1. Set the HMAC secret (required for wardex accept)
export WARDEX_HMAC_SECRET="$(openssl rand -hex 32)"

# 2. Run the full suite
cd test/poc
chmod +x run-all-scenarios.sh
./run-all-scenarios.sh
```

The script will:
1. Build `wardex` from source
2. Run Scenarios 01–03 via the CLI
3. Run Scenario 04 as a multi-step flow:
   - Gate → BLOCK (baseline)
   - `wardex accept request` → registers exception
   - Gate → ALLOW (exception honoured)
   - `wardex accept verify` → HMAC integrity check
4. Run the SDK integration test (`main.go`)
5. Print a summary of pass/fail results

---

## Understanding the Risk Formula

Wardex uses a composite risk formula, **not raw CVSS**:

```
composite = (CVSS/10 × EPSS) × (1 - compEffect) × criticality × exposure
```

Where:
- **EPSS** = exploit probability (0.0–1.0)
- **compEffect** = combined effectiveness of compensating controls (clamped at 0.8)
- **criticality** = business impact of the asset (0.0–1.0)
- **exposure** = `internetWeight × (1 - authReduction) × (1 - reachableReduction)`

| Factor | Value |
|--------|-------|
| `internetWeight` | 1.0 (internet/public) or 0.6 (internal) or 0.3 (dev) |
| `authReduction` | 0.2 if `RequiresAuth = true`, else 0.0 |
| `reachableReduction` | 0.5 if `Reachable = false`, else 0.0 |
| `criticality` | 1.5 (High/Regulated), 1.0 (Moderate), 0.3 (Low) |

**Decision**: If `composite > risk_appetite` → **BLOCK**, otherwise **ALLOW**.
Scale for $R \in [0, 1.5]$. Typical thresholds: 0.05 (Finance), 0.08 (Health), 0.20 (SaaS).

---

## Scenario Walkthroughs

### Scenario 01 — Happy Path → ALLOW

```
CVSS = 0.32 (3.2/10), EPSS = 0.018, Reachable = false
Criticality = 0.3, Internet = false, Auth = true

adjusted     = 0.32 × 0.018 = 0.0057
exposure     = 0.6 × (1-0.2) × (1-0.5) = 0.24
compEffect   = 0.0 (no controls)
finalRisk    = 0.0057 × 0.3 × 0.24 ≈ 0.0004

0.0004 < 0.20 → ALLOW [PASS]
```

### Scenario 02 — Critical CVE → BLOCK

```
CVSS = 0.98 (9.8/10), EPSS = 0.91, Reachable = true
Criticality = 1.5 (Finance), Internet = true, Auth = false

adjusted     = 0.98 × 0.91 = 0.8918
exposure     = 1.0 × 1.0 × 1.0 = 1.0
compEffect   = 0.0 (no controls)
finalRisk    = 0.8918 × 1.5 × 1.0 = 1.337

1.337 > 0.05 → BLOCK [PASS]
```

### Scenario 03 — Compensating Controls → ALLOW

```
CVSS = 0.81 (8.1/10), EPSS = 0.45, Reachable = true
Criticality = 1.0 (SaaS), Internet = true, Auth = true
Controls: WAF(0.40) + auth(0.30) + segmentation(0.15) = 0.85 → clamped to 0.8

adjusted     = 0.81 × 0.45 = 0.3645
compensated  = 0.3645 × (1 - 0.8) = 0.0729
exposure     = 1.0 × (1-0.2) × 1.0 = 0.8
finalRisk    = 0.0729 × 1.0 × 0.8 = 0.058

0.058 < 0.20 → ALLOW [PASS]
```

### Scenario 04 — Risk Acceptance Baseline → BLOCK

```
CVSS = 0.91 (9.1/10), EPSS = 0.84, Reachable = true
Criticality = 1.5 (Health), Internet = true, Auth = true
Controls: none

adjusted     = 0.91 × 0.84 = 0.7644
compensated  = 0.7644 × 1.0 = 0.7644
exposure     = 1.0 × (1-0.2) × 1.0 = 0.8
finalRisk    = 0.7644 × 1.5 × 0.8 = 0.917

0.917 > 0.08 → BLOCK [PASS] (baseline for acceptance)
```

---

## GitHub Actions

The `wardex-gate.yml` file contains a ready-to-use GitHub Actions workflow that runs
all 4 scenarios as parallel jobs. To use it:

1. Copy `wardex-gate.yml` to `.github/workflows/` in your POC repository
2. Add `WARDEX_HMAC_SECRET` as a repository secret
3. Push to `main` or `develop` to trigger the pipeline

The final `release-decision` job aggregates all scenario results and fails the
pipeline if any scenario produces an unexpected outcome.

---

## Key Concepts Validated

| Concept | Validated By |
|---------|-------------|
| Composite risk scoring (CVSS × EPSS × criticality × exposure) | All scenarios |
| Compensating control dampening (multiplicative reduction) | Scenario 03 |
| Risk appetite threshold enforcement | Scenarios 02, 04 |
| Risk acceptance with HMAC-SHA256 signing | Scenario 04 (CLI) |
| Append-only audit logging (JSONL) | Scenario 04 (CLI) |
| SDK-level API integration | All scenarios (main.go) |
