# Wardex Input Guide

**Audience:** anyone declaring controls in `documented-controls.yaml`, `implemented-controls.yaml`, or `assets.yaml` for Wardex analysis.

**Purpose:** explain how to declare control data so that the input survives all three tiers of the Wardex linter — and, more importantly, so that the resulting analysis is defensible to an auditor.

This guide is not optional reading if you are responsible for maintaining Wardex inputs. The linter will tell you when you have made a mistake; this document explains *why* it is a mistake and what the correct version looks like.

---

## 1. The mental model

Wardex distinguishes two layers of control:

**Documented** — a control that exists in policy, procedure, or design documentation. It says what the organisation *intends* to do.

**Implemented** — a control that is operationally active and produces evidence of its operation. It records what the organisation *actually does*.

The same control ID can exist in both layers. That is the expected case for a well-run organisation: the policy is documented and the operational reality matches it. When the same ID exists in only one layer, Wardex flags it: documented-only is paper security; implemented-only is shadow security.

The input guide below applies to both layers. The fields differ slightly in meaning depending on which layer you are declaring.

---

## 2. The minimum viable control declaration

Every control needs four fields:

```yaml
- id: DOC-IAM-001
  name: Multi-Factor Authentication for Privileged Accounts
  layer: documented
  maturity: 4
```

That is the absolute minimum. The linter Tier 1 will accept this. It will not be useful — without `domains`, the correlator cannot match it against the framework catalogue — but it will load.

In practice you should always include:

```yaml
- id: DOC-IAM-001
  name: Multi-Factor Authentication for Privileged Accounts
  description: >
    All accounts with admin or production access require MFA via Okta.
    Reviewed quarterly by IAM team.
  layer: documented
  domains: [technological]
  maturity: 4
  evidences:
    - type: policy
      ref: iam-policy-v3.0
```

---

## 3. The fields, one by one

### 3.1 `id` (required)

A unique identifier for the control within its layer. Two controls with the same `id` and same `layer` is a Tier 1 error (LINT-006). The same `id` across layers is fine and expected.

Convention: prefix with the layer's source. `DOC-` for documented controls, `IMPL-` for implemented controls discovered separately, or use the framework's own ID convention (`A.5.1`, `A.8.8`) when the mapping is one-to-one.

### 3.2 `name` (required)

Human-readable name. Should be specific enough that someone reading the report knows what control is being discussed without checking the ID. *"Information Security Policy"* is too vague. *"Top-level Information Security Policy approved by CISO"* is better.

### 3.3 `layer` (required, recommended explicit)

Either `documented` or `implemented`. Any other value is a Tier 1 error (LINT-002).

If you omit `layer`, Wardex defaults to `documented` — which means the control is treated as policy-only and will not contribute to operational coverage. This default exists because the historical wardex assumption was that all controls were operational, and reversing that assumption was the central change in v1.8.0. If your control is operationally active, declare `layer: implemented` explicitly. Do not rely on the default.

### 3.4 `maturity` (required)

Integer 0–5 representing the maturity of the control. Out-of-range values are a Tier 1 error (LINT-003).

The scale follows OWASP SAMM / ISO 21827 conventions:

| Value | Meaning |
|---|---|
| 0 | Not implemented at all (only valid for documented-only declarations) |
| 1 | Ad-hoc, undocumented, applied inconsistently |
| 2 | Repeatable but informal — done by individuals, not the organisation |
| 3 | Documented and consistently applied across the relevant scope |
| 4 | Measured — the organisation tracks performance and reviews periodically |
| 5 | Continuously improved with formal feedback loops and metrics |

**Common error:** declaring `maturity: 5` because the control is "really good." If you cannot point to evidence of formal feedback loops and improvement metrics, the value is at most 4. The Tier 2 linter (LINT-101, LINT-102) flags suspicious maturity claims.

### 3.5 `domains` (recommended)

A list of domain tags used by the correlator for high-confidence matching. ISO 27001 domains are `organizational`, `people`, `physical`, `technological`. Other frameworks have their own.

A control without `domains` falls through to keyword-based correlation, which is much weaker. Always declare domains when you know them.

### 3.6 `effectiveness` (implemented controls only)

A float 0.0–1.0 representing how well the control performs in operation. Out-of-range values are a Tier 1 error (LINT-004). Declaring `effectiveness > 0` on a non-implemented control is also a Tier 1 error (LINT-007).

This is the most lied-about field in any compliance system. The linter has multiple heuristics to detect lazy declarations.

**The honest version:** effectiveness should be derivable from observable data. *"WAF blocks 87% of malicious requests over 30 days"* gives you `effectiveness: 0.87` with a defensible basis. *"MFA enrolment is 100% for production accounts"* supports `effectiveness: 0.95` because the control covers the population it should cover but cannot defend against social engineering — the residual 0.05 is the honest gap.

**The lazy version:** declaring `0.90` for everything because it sounds good. The Tier 3 linter computes the Gini coefficient of effectiveness values (STAT-201) and flags inputs with very low variance. It also computes round-number bias (STAT-206) — if 70%+ of your values end in `.00`, `.50`, `.75`, `.90`, or `.95`, the linter flags it as suggesting non-derived values.

Effectiveness without evidence is also flagged (LINT-008). If you declare `effectiveness: 0.85`, you should be able to point to the evidence that justifies the number.

### 3.7 `evidences` (required for implemented controls with effectiveness > 0)

A list of evidence references. Each evidence has a `type` and a `ref`:

```yaml
evidences:
  - type: log
    ref: okta-mfa-enrolment-2025-q1
  - type: test_result
    ref: phishing-sim-march-2025
```

Common types: `policy`, `procedure`, `architecture`, `log`, `test_result`, `screenshot`, `interview`, `review`. The linter does not enforce a closed list — use what makes sense for your organisation.

**The `ref` field should be specific enough that an auditor can find the evidence.** *"see SharePoint"* is not a useful ref. *"sharepoint:/sec/audit/2025-q1/mfa-enrolment-export.csv"* is.

LINT-107 flags evidence references reused across 3+ controls. This usually means the analyst pasted the same ref everywhere because the control list grew faster than the evidence collection. Resolve by either gathering distinct evidence per control or by consolidating overlapping controls.

### 3.8 `context_weight` (optional)

A float 0.5–2.0 representing the relevance multiplier for this control in the organisation's context. Out-of-range values are a Tier 1 error (LINT-005).

Default: `1.0` (treat as standard relevance). Use higher values for controls that are critical for your specific business — for example, a payment processor would weight cryptography controls higher than a content publisher would.

If you set `context_weight != 1.0`, you should also fill `weight_justification`. Otherwise LINT-106 flags the control: deviation from the default without explanation is suspicious.

### 3.9 `review_required` (optional)

Set `true` when the declared values are tentative and need expert review before being trusted. Typically set by automated ingestion tools (like Bridgr) when the source could not reliably determine maturity or effectiveness.

LINT-010 flags `review_required: true` combined with `effectiveness > 0.7` — the combination is internally contradictory. If the values need review, do not also declare them as high-confidence.

---

## 4. Asset declarations

Assets live in a separate file and represent the systems against which controls apply.

### 4.1 The minimum viable asset

```yaml
- id: ASSET-001
  name: Payment API
  type: application
  criticality: 1.0
  controls: [DOC-IAM-001, DOC-CRYPTO-001]
  exposure:
    internet_facing: true
    requires_auth: true
    network_zone: dmz
    data_classification: restricted
```

### 4.2 Criticality scale

| Value | Meaning |
|---|---|
| 0.25 | Internal experiments, sandboxes, throwaway systems |
| 0.50 | Internal business systems with no external exposure |
| 1.00 | Customer-facing or revenue-impacting systems |
| 1.50 | Regulated, safety-critical, or systemically important |

This is the `C(α)` term in the gate formula. Inflating it makes everything block; deflating it makes nothing block. The discipline is to assign a value you would defend in a board meeting.

### 4.3 Exposure block

The `exposure` block derives `E(α)` for the gate formula on a per-asset basis. The linter does not validate the values themselves — it validates that they exist when other fields suggest they should.

`network_zone` values: `air-gapped`, `internal`, `dmz`, `public`. Higher exposure means higher base risk in the gate calculation.

### 4.4 Threats and compensating controls

If you declare threats on an asset, declare compensating controls that mitigate each one. LINT-110 flags threats without matching `compensating_controls.threat_ref`:

```yaml
threats:
  - id: T-001
    scenario: "Unauthenticated API abuse"
    mitre_technique: T1190
    likelihood: high

compensating_controls:
  - type: waf
    effectiveness: 0.35
    ref: DOC-WAF-001       # references an ExistingControl
    threat_ref: T-001      # mitigates T-001 specifically
```

The linker between threats and controls is the `threat_ref` field. Without it, the linter cannot tell whether a declared threat has been considered in the control set.

LINT-109 flags assets that reference control IDs not present in the loaded control files. Usually means a typo or a control that was renamed without updating the asset file.

---

## 5. The three tiers, summarised for analysts

When you run `wardex assess`, three separate checks happen:

**Tier 1 (Schema)** runs as part of ingestion. If your YAML is malformed — missing required fields, out-of-range values, contradictory layer/effectiveness — the analysis does not run. The CLI exits with code 20 and lists every violation. Fix all violations before retrying; the linter does not stop at the first.

**Tier 2 (Coherence)** runs after analysis succeeds. It produces named warnings for declarations that pass schema but are internally suspicious. Warnings appear in the report under `## Input Quality` and on stderr. The analysis result is still produced.

**Tier 3 (Statistical)** runs over the full input set. It computes distributional metrics — variance of effectiveness values, entropy of maturity distribution, evidence type diversity — and produces an Input Quality Score from 0 to 100. The score appears in the report header.

### 5.1 What the score means

| Band | Score | Implication |
|---|---|---|
| Strong | 90–100 | Input is well-structured. Analysis results are defensible. |
| Acceptable | 70–89 | Some warnings worth reviewing. Most analyses fall here. |
| Concerning | 50–69 | Multiple issues. Review before presenting results to auditors. |
| Weak | 0–49 | Significant problems. Results may not survive scrutiny. |

The score is not a verdict on your security posture. It is a verdict on the quality of your declarations. A weak score on a strong security programme means the documentation has not caught up to reality. A strong score on a weak programme means you have lied carefully.

### 5.2 What the score is not

The score does not measure operational effectiveness. The linter never observes whether your WAF actually blocks attacks, whether your MFA is actually enforced, whether your incident response plan works. It measures coherence of declarations.

If you treat Wardex as a substitute for evidence collection, you have made a category error. The linter exists to catch declaration mistakes, not to validate operational reality.

---

## 6. Practical workflow

### 6.1 First-time setup

1. Start with `documented-controls.yaml` from your existing policy inventory. Run `wardex assess --no-lint documented.yaml` to confirm ingestion works.
2. Enable lint and resolve all Tier 1 violations.
3. Resolve Tier 2 warnings one by one. Each warning has a rule ID — use `wardex lint --explain LINT-XXX` to see the full rule definition and remediation guidance.
4. Note the Input Quality Score baseline.
5. Build `implemented-controls.yaml` from operational sources. Re-run with both files.
6. Iterate until the score reaches at least Acceptable (70+).

### 6.2 Ongoing maintenance

1. Add new controls as you implement them. Keep `evidences` references current.
2. When effectiveness changes, update the value and add an evidence ref dated within the year. LINT-103 flags stale evidence.
3. Run `wardex assess --lint-min-quality 70` in CI. The build fails if input quality drops below the threshold.
4. Quarterly: review all controls with `review_required: true` and either confirm values or downgrade them.

### 6.3 Resolving common warnings

| Warning | Most likely cause | Fix |
|---|---|---|
| LINT-101 | Marked `implemented` to inflate coverage, but the control barely works | Change to `documented` or fix the control |
| LINT-102 | Optimistic effectiveness with low maturity | Lower one or raise the other; both should not coexist |
| LINT-103 | Evidence not updated | Refresh the evidence reference, or accept the warning if the control is genuinely stable |
| LINT-104 | All evidence is the same kind | Add evidence of a different type to corroborate |
| LINT-107 | Same evidence cited many times | Either consolidate the controls or collect distinct evidence |
| LINT-108 | Effectiveness declared without supporting data | Either gather evidence or set `effectiveness: 0` until you have it |
| STAT-201 | Effectiveness values too uniform | Re-derive values from observation; the real distribution should have variance |
| STAT-206 | Round numbers used everywhere | Effectiveness derived from data is rarely a round number |

---

## 7. The auditor perspective

An auditor reviewing a Wardex report sees the Input Quality Score and the warning list. A high score with zero warnings tells them nothing on its own — it is necessary but not sufficient. What it does is shift the conversation: instead of *"convince me your declarations are accurate,"* the auditor moves to *"show me the evidence behind these specific claims."*

The point of the linter is not to convince an auditor that you are honest. The point is to make dishonesty visible enough that the question stops being interesting. If your declarations pass all three tiers, the conversation is about evidence quality, not about whether you bothered to think.

---

## 8. Reference

- Spec: `SPEC_wardex_v1.8.1_lint.md`
- Rule catalogue: `pkg/lint/rules.go`
- Inspect a specific rule: `wardex lint --explain LINT-XXX`
- Command reference: `wardex assess --help`

---

## 9. Vulnerability Envelope (v2.0 — CRA Article 14)

The vulnerability envelope YAML now supports three optional fields for CRA active exploitation classification:

```yaml
vulnerabilities:
  - cve_id: CVE-2024-3094
    cvss_base: 10.0
    epss_score: 0.95
    component: xz-utils
    reachable: true
    # NEW in v2.0 — CRA Article 14
    actively_exploited: true                # classified as actively exploited
    actively_exploited_since: "2024-03-29T00:00:00Z"  # when exploitation was confirmed
    exploited_source: "cisa-kev"           # source of the classification
```

`actively_exploited` is set to `true` automatically when KEV correlation is enabled (`--kev` flag) and the CVE is found in the CISA KEV catalogue. It can also be set manually in the envelope for CVEs classified through other means.

`exploited_source` traces the origin: `"cisa-kev"`, `"manual"`, or any custom identifier.

`actively_exploited_since` records when exploitation was first confirmed (distinct from when Wardex detected it). When set via KEV, this is populated from the KEV `dateAdded` field.

*This document is part of the Wardex v2.0 release.*

---

## 10. Reference

- Spec: `SPEC_wardex_v2.0_CRA_Art14.md`
- Changelog: `CHANGELOG.md`
- Command reference: `wardex evaluate --help`, `wardex art14 --help`
