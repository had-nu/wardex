# SPEC — Wardex v1.8.1: Input Coherence Linter

**Status:** DRAFT
**Author:** André Ataíde
**Date:** 2026-04-25
**Targets:** v1.8.1
**Prerequisite reading:** `SPEC_wardex_v3_gap.md` (v1.8.0), `doc/INPUT_GUIDE.md` (delivered with this spec)

---

## 1. Context

Wardex v1.8.0 introduced layer-aware analysis, asset compliance, and the paper/shadow security model. The model assumes the input YAML reflects what the analyst genuinely knows. The model has no defence against the analyst who declares `effectiveness: 0.95` for fifty controls without thinking, or who fills `layer: implemented` because that is what scores best.

This spec adds a three-layer linter that makes such declarations harder to construct without leaving traces. The linter does not verify operational reality — that requires evidence collection outside Wardex's scope. It verifies that declarations are well-formed, internally coherent, and statistically plausible. Violations leave a recorded trail in the report.

The position is honest: *the linter detects malformed, internally contradictory, or statistically implausible control declarations. It does not validate that declared values reflect reality.*

---

## 2. Scope

| # | Area | Change type |
|---|------|-------------|
| 2.1 | New package | `pkg/lint/` — three-tier rule engine |
| 2.2 | Schema (Tier 1) | Hard rules that fail ingestion |
| 2.3 | Coherence (Tier 2) | Internal contradiction detection — warnings with rule names |
| 2.4 | Statistical (Tier 3) | Distribution analysis over the full input set |
| 2.5 | Report integration | New `## Input Quality` section in markdown/json/csv outputs |
| 2.6 | CLI | `--lint` flag (default on); `--no-lint` to opt out |
| 2.7 | Documentation | New `doc/INPUT_GUIDE.md` — how to declare controls correctly |
| 2.8 | Rule catalog | Initial set of ~20 rules with stable IDs (LINT-001...LINT-020) |

**Out of scope:**
- Configurable thresholds for Tier 3 (defaults only in this version)
- Custom rule definitions by users (rules are bundled with the binary)
- Cross-file lint (e.g. detecting that the same evidence ref is used in 50 controls — this is single-file analysis)
- Integration with Bridgr output validation (separate spec when Bridgr is integrated)

---

## 3. Design Principles

**Tier 1 fails fast.** A schema violation is an error, not a warning. The ingestion does not return controls that violate Tier 1 rules. The CLI exits non-zero. There is no `--ignore-tier1` flag.

**Tier 2 produces named warnings.** Each warning carries the rule ID, the affected control ID, and a one-line reason. Tier 2 does not block analysis; it annotates. The report shows the warning count prominently.

**Tier 3 produces an input quality score.** A single number 0–100 with decomposition. Computed over the full input set. Does not block analysis. Appears in the report as context.

**Rule IDs are stable.** Once published, a rule ID always refers to the same rule. Rules are deprecated, never renumbered. This lets organisations build internal exception lists referencing rule IDs.

**Calibration over false positives.** Tier 3 thresholds are wide enough to avoid flagging legitimate small datasets or genuinely well-implemented control sets. The cost of false negatives is acceptable — the linter is one of several signals, not the sole source of truth.

---

## 4. Tier 1 — Schema (Hard Rules)

These rules run during ingestion. A violation prevents the control from being loaded. The ingestion returns an error listing all violations, not just the first.

### 4.1 Initial rule set

| ID | Rule | Failure condition |
|---|---|---|
| LINT-001 | Required fields present | Missing `id`, `name`, `layer`, or `maturity` |
| LINT-002 | Layer value valid | `layer` not in `{documented, implemented}` |
| LINT-003 | Maturity range | `maturity` not in `[0, 5]` |
| LINT-004 | Effectiveness range | `effectiveness` declared outside `[0.0, 1.0]` |
| LINT-005 | ContextWeight range | `context_weight` declared outside `[0.5, 2.0]` |
| LINT-006 | ID uniqueness within layer | Two controls with same `id` and same `layer` |
| LINT-007 | Effectiveness requires implementation | `effectiveness > 0` but `layer != implemented` |
| LINT-008 | Implemented requires evidence | `layer == implemented` and `effectiveness > 0` but `evidences` is empty |
| LINT-009 | Evidence ref non-empty | An `evidences` entry with empty `ref` field |
| LINT-010 | ReviewRequired implies low confidence | `review_required: true` and `effectiveness > 0.7` |

### 4.2 Tier 1 implementation contract

```go
// pkg/lint/tier1.go

// SchemaViolation describes a single Tier 1 failure.
type SchemaViolation struct {
    RuleID    string // e.g. "LINT-008"
    ControlID string // ID of the control that violated, or "" for global rules
    Field     string // optional: specific field name
    Message   string // human-readable reason
}

// CheckSchema validates a slice of ExistingControl against all Tier 1 rules.
// Returns all violations found — does not stop at the first.
// An empty slice means the input passes Tier 1.
func CheckSchema(controls []model.ExistingControl) []SchemaViolation
```

Ingestion calls `CheckSchema` after loading and unmarshalling. If violations are non-empty, the loader returns an error with the formatted violation list. The CLI exit code is `EXIT_INPUT_INVALID` (new constant in `pkg/exitcodes`).

---

## 5. Tier 2 — Coherence (Warnings)

These rules run after Tier 1 passes. They detect declarations that are individually well-formed but internally contradictory or suspicious.

### 5.1 Initial rule set

| ID | Rule | Trigger condition |
|---|---|---|
| LINT-101 | Implemented with low maturity | `layer: implemented` and `maturity <= 1` |
| LINT-102 | High effectiveness, low maturity | `effectiveness >= 0.8` and `maturity <= 2` |
| LINT-103 | Stale evidence | Evidence with timestamp/ref older than 365 days (when parseable) |
| LINT-104 | Single evidence type clustering | Control with 3+ evidences all of the same `type` |
| LINT-105 | Domain-effectiveness mismatch | `domains: [physical]` with `evidence type: code` (or vice versa) |
| LINT-106 | ContextWeight without justification | `context_weight != 1.0` and `weight_justification` empty |
| LINT-107 | Evidence reference reuse | Same `evidences[].ref` value appears in 3+ controls |
| LINT-108 | Owner clustering with uniform effectiveness | All controls with same owner have effectiveness within ±0.05 |
| LINT-109 | Asset references unknown control | `asset.controls[]` contains an ID not present in loaded controls |
| LINT-110 | Threat without compensating control | `asset.threats[]` declared with no `compensating_controls[].threat_ref` matching |

### 5.2 Tier 2 implementation contract

```go
// pkg/lint/tier2.go

// CoherenceWarning describes a single Tier 2 finding.
type CoherenceWarning struct {
    RuleID    string
    ControlID string // empty for asset-scoped warnings
    AssetID   string // empty for control-scoped warnings
    Severity  string // "low" | "medium" | "high"
    Message   string
}

// CheckCoherence runs all Tier 2 rules over the loaded controls and assets.
// Returns warnings; does not error or block.
func CheckCoherence(controls []model.ExistingControl, assets []model.Asset) []CoherenceWarning
```

Severity is fixed per rule, not configurable. The mapping is documented in `INPUT_GUIDE.md` so analysts know which warnings warrant immediate attention.

---

## 6. Tier 3 — Statistical Plausibility

These checks run over the full input set after Tier 1 and Tier 2 complete. They produce metrics, not pass/fail outcomes.

### 6.1 Initial metric set

| ID | Metric | Computation | Suspicion threshold |
|---|---|---|---|
| STAT-201 | Effectiveness Gini coefficient | Standard Gini over `effectiveness` values of implemented controls | `< 0.10` flags low variance |
| STAT-202 | Maturity entropy | Shannon entropy of maturity distribution `[0..5]` | `< 0.5 bits` flags uniform/clustered |
| STAT-203 | Effectiveness clustering | Standard deviation per `owner` | `σ < 0.05` for any owner with 3+ controls |
| STAT-204 | Layer balance | Ratio of implemented to documented controls | `< 0.2` or `> 5.0` flags imbalance |
| STAT-205 | Evidence diversity | Unique `evidences[].type` values divided by total evidences | `< 0.3` flags monoculture |
| STAT-206 | Round-number bias | Percentage of `effectiveness` values ending in `.00`, `.50`, `.75`, `.90`, `.95` | `> 70%` flags lazy inputs |

### 6.2 Input Quality Score

Aggregate score 0–100 computed as:

```
InputQualityScore = 100
                  - (5 × Tier2_warnings_high)
                  - (2 × Tier2_warnings_medium)
                  - (1 × Tier2_warnings_low)
                  - Tier3_penalty
```

Where `Tier3_penalty` is the sum of penalties from each STAT rule that exceeded its suspicion threshold (5 points per metric flagged).

Score is clamped to `[0, 100]`. The report describes the score with a band:

| Band | Score | Meaning |
|---|---|---|
| Strong | 90–100 | Input is well-structured and statistically plausible |
| Acceptable | 70–89 | Some warnings worth reviewing but no systemic concerns |
| Concerning | 50–69 | Multiple warnings or distribution anomalies — review recommended |
| Weak | 0–49 | Significant input quality issues — analysis results may not be defensible |

### 6.3 Tier 3 implementation contract

```go
// pkg/lint/tier3.go

// StatisticalReport describes the Tier 3 outcome.
type StatisticalReport struct {
    Metrics      map[string]float64 // STAT-201 → 0.08, STAT-202 → 0.42, ...
    Flags        []string            // metric IDs that exceeded their suspicion threshold
    QualityScore int                  // 0..100
    Band         string               // "strong" | "acceptable" | "concerning" | "weak"
}

func ComputeStatistics(
    controls []model.ExistingControl,
    tier2Warnings []CoherenceWarning,
) StatisticalReport
```

---

## 7. CLI Integration

### 7.1 Default behaviour

`wardex assess` runs all three tiers by default. Output:

- Tier 1 violations → ingestion fails, exit code `EXIT_INPUT_INVALID`, no report generated
- Tier 2 warnings → printed to stderr at `[WARN]` level + included in report
- Tier 3 metrics → included in report under `## Input Quality`

### 7.2 New flags

```
--no-lint              Skip all linting (Tier 1 still runs as ingestion check)
--lint-strict          Treat Tier 2 warnings as errors (exit non-zero if any)
--lint-min-quality N   Exit non-zero if InputQualityScore < N (CI threshold)
```

`--no-lint` cannot disable Tier 1 — schema validation is part of ingestion, not optional.

### 7.3 Exit codes

New constants in `pkg/exitcodes`:

```go
ExitInputInvalid     = 20  // Tier 1 schema violation
ExitInputLowQuality  = 21  // --lint-min-quality threshold not met
ExitInputStrict      = 22  // --lint-strict and Tier 2 warnings present
```

---

## 8. Report Integration

### 8.1 Markdown renderer

New section after `## Executive Summary`, before `## Coverage by Domain`:

```markdown
## Input Quality

**Score:** 73/100 (Acceptable)

### Tier 2 Warnings (4)

| Rule | Control / Asset | Severity | Message |
|---|---|---|---|
| LINT-101 | DOC-TECH-005 | medium | Implemented with maturity 1 — declared operational but rated lowest |
| LINT-107 | (multiple) | low | Evidence ref `okta-mfa-2025` reused in 3 controls |
| LINT-110 | ASSET-001 | high | Threat T-003 declared but no compensating_control with threat_ref: T-003 |
| LINT-108 | (owner: hr-infra) | medium | All 4 controls owned by hr-infra have effectiveness within ±0.03 |

### Statistical Indicators

| Metric | Value | Status |
|---|---|---|
| Effectiveness Gini coefficient | 0.08 | [WARN] flagged (< 0.10) |
| Maturity entropy | 1.2 bits | OK |
| Round-number bias | 78% | [WARN] flagged (> 70%) |

*Input quality is a measure of declaration coherence, not operational reality.
See doc/INPUT_GUIDE.md for guidance on resolving flagged items.*
```

### 8.2 JSON renderer

Add `input_quality` top-level object with the full `StatisticalReport` plus the warning array.

### 8.3 CSV renderer

Add a separate sheet/section `input_quality.csv` with one row per warning and one row per metric.

---

## 9. Rule Catalogue Maintenance

Rules live in `pkg/lint/rules.go` as a versioned catalog. Each rule is a value, not a function reference, with metadata that the renderer uses:

```go
type Rule struct {
    ID          string
    Tier        int     // 1, 2, or 3
    Severity    string  // "error" (tier 1), "low|medium|high" (tier 2), n/a (tier 3)
    Title       string
    Description string  // shown in --explain output
    Reference   string  // link to INPUT_GUIDE.md anchor
}

var Catalog = []Rule{
    {ID: "LINT-001", Tier: 1, Severity: "error", Title: "Required fields present", ...},
    {ID: "LINT-002", Tier: 1, Severity: "error", Title: "Layer value valid", ...},
    // ...
}
```

A new CLI command `wardex lint --explain LINT-101` prints the full rule definition. Useful for analysts who see a warning and want to understand it without leaving the terminal.

---

## 10. Test Requirements

Each rule requires three test cases:

1. **Positive trigger** — input that should violate the rule
2. **Negative case** — input that is similar but does not violate
3. **Edge case** — boundary value (e.g. effectiveness exactly 0.7 for LINT-010)

Tier 3 metrics require statistical baseline tests:

- Synthetic dataset with uniform effectiveness → STAT-201 fires
- Synthetic dataset with realistic variance → STAT-201 does not fire
- Single-control input → all Tier 3 metrics return without error (small-sample handling)

Integration test:
- `test/testdata/bad_input.yaml` — designed to fail Tier 1 with multiple violations; ingestion must report all of them
- `test/testdata/lazy_input.yaml` — passes Tier 1 but should produce InputQualityScore < 50

---

## 11. CI Mirror

```yaml
- name: Verify rule catalog has no duplicate IDs
  run: |
    go run ./pkg/lint/cmd/check-catalog
    # Custom helper that loads Catalog and asserts uniqueness

- name: Lint smoke test (good input)
  run: |
    wardex assess test/testdata/documented-controls.yaml \
                  test/testdata/implemented-controls.yaml \
                  --assets test/testdata/assets.yaml \
                  --lint-min-quality 70 -o json > /dev/null
    # Must exit 0

- name: Lint smoke test (bad input)
  run: |
    wardex assess test/testdata/bad_input.yaml -o json && exit 1 || exit 0
    # Must exit 20 (EXIT_INPUT_INVALID)
```

---

## 12. Delivery Order

1. `pkg/lint/tier1.go` + integration into `pkg/ingestion/`
2. `pkg/lint/tier2.go` with the initial 10 rules
3. `pkg/lint/tier3.go` with the initial 6 metrics + quality score
4. CLI flags and exit codes
5. Report integration (markdown first, then json, then csv)
6. `doc/INPUT_GUIDE.md` (delivered alongside this spec — see companion document)
7. `wardex lint --explain` subcommand
8. CI smoke tests + bad/lazy input fixtures
9. Tag v1.8.1

Each phase leaves the build green before the next begins.

---

## 13. Open Questions

**Q1 — Default for `--lint`**

The spec defaults to lint enabled. This will surface warnings in any existing CI pipeline that upgrades to v1.8.1, which is the intended behavioural effect — but it is a breaking change in terms of report content. Confirm: lint enabled by default, with `--no-lint` as the opt-out?

**Q2 — Round-number bias threshold**

STAT-206 flags inputs where >70% of effectiveness values end in common round figures. This threshold is intuitive but arbitrary. Should it be calibrated against a baseline dataset before tagging v1.8.1?

**Q3 — `wardex lint` as a standalone subcommand**

Currently the linter only runs as part of `wardex assess`. Worth adding a standalone `wardex lint controls.yaml` command that runs only the linter without the framework analysis? Useful for pre-commit hooks. If yes, scope creep for v1.8.1 or push to v1.8.2?

---

*End of spec.*
