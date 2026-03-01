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
| 01 | Happy Path | CVSS 3.2, EPSS 0.018, no reach | **ALLOW** | ~0.00 |
| 02 | Critical Block | CVSS 9.8, EPSS 0.91, internet, no auth | **BLOCK** | ~8.47 |
| 03 | Compensating Controls | CVSS 8.1 + WAF + auth + segmentation | **ALLOW** | ~0.44 |
| 04 | Risk Acceptance | CVSS 9.1, no controls, no auth → exception | **BLOCK** (baseline) | ~6.50 |

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
composite = (CVSS × EPSS) × (1 - compEffect) × criticality × exposure
```

Where:
- **EPSS** = exploit probability (0.0–1.0)
- **compEffect** = combined effectiveness of compensating controls (clamped at 0.8)
- **criticality** = business impact of the asset (0.0–1.0)
- **exposure** = `internetWeight × (1 - authReduction) × (1 - reachableReduction)`

| Factor | Value |
|--------|-------|
| `internetWeight` | 1.0 (internet-facing) or 0.6 (internal) or 0.3 (dev) |
| `authReduction` | 0.2 if `RequiresAuth = true`, else 0.0 |
| `reachableReduction` | 0.5 if `Reachable = false`, else 0.0 |

**Decision**: If `composite > risk_appetite` → **BLOCK**, otherwise **ALLOW**.

---

## Scenario Walkthroughs

### Scenario 01 — Happy Path → ALLOW

```
CVSS = 3.2, EPSS = 0.018, Reachable = false
Criticality = 0.3, Internet = false, Auth = true

adjusted     = 3.2 × 0.018 = 0.058
exposure     = 0.6 × (1-0.2) × (1-0.5) = 0.24
compEffect   = 0.0 (no controls)
finalRisk    = 0.058 × 0.3 × 0.24 ≈ 0.004

0.004 < 6.0 → ALLOW [PASS]
```

### Scenario 02 — Critical CVE → BLOCK

```
CVSS = 9.8, EPSS = 0.91, Reachable = true
Criticality = 0.95, Internet = true, Auth = false

adjusted     = 9.8 × 0.91 = 8.918
exposure     = 1.0 × 1.0 × 1.0 = 1.0
compEffect   = 0.0 (no controls)
finalRisk    = 8.918 × 0.95 × 1.0 = 8.47

8.47 > 6.0 → BLOCK [PASS]
```

### Scenario 03 — Compensating Controls → ALLOW

```
CVSS = 8.1, EPSS = 0.45, Reachable = true
Criticality = 0.75, Internet = true, Auth = true
Controls: WAF(0.40) + auth(0.30) + segmentation(0.15) = 0.85 → clamped to 0.8

adjusted     = 8.1 × 0.45 = 3.645
compensated  = 3.645 × (1 - 0.8) = 0.729
exposure     = 1.0 × (1-0.2) × 1.0 = 0.8
finalRisk    = 0.729 × 0.75 × 0.8 = 0.437

0.437 < 6.0 → ALLOW [PASS]
```

### Scenario 04 — Risk Acceptance Baseline → BLOCK

```
CVSS = 9.1, EPSS = 0.84, Reachable = true
Criticality = 0.85, Internet = true, Auth = false
Controls: none

adjusted     = 9.1 × 0.84 = 7.644
compensated  = 7.644 × 1.0 = 7.644
exposure     = 1.0 × 1.0 × 1.0 = 1.0
finalRisk    = 7.644 × 0.85 × 1.0 = 6.50

6.50 > 6.0 → BLOCK [PASS] (baseline for acceptance)
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
