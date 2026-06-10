# SPEC — Wardex v2.0: CRA Article 14 Enablement

**Status:** Draft  
**Author:** Root Security Governance Advisory  
**Version target:** v2.0.0  
**Regulatory anchor:** Regulation (EU) 2024/2847 — Cyber Resilience Act, Article 14  
**Application deadline:** 11 September 2026  
**Principle:** Enable, never execute. Wardex prepares the artefact; the operator pulls the trigger.

---

## 1. Context and Scope

Wardex v1.9.2 is a release gate: it evaluates vulnerability risk, produces an auditable decision, and blocks or allows a pipeline. It does not classify vulnerabilities as actively exploited in the legal sense of the CRA, does not generate notification artefacts, and has no output structure aligned with the three-phase timeline mandated by Article 14(2).

Article 14 enters application on **11 September 2026**. It imposes three obligations on manufacturers who become aware of an actively exploited vulnerability in a product with digital elements:

- **Early warning** within 24 hours of awareness (Art. 14(2)(a))
- **Vulnerability notification** within 72 hours of awareness (Art. 14(2)(b))
- **Final report** no later than 14 days after a corrective measure is available (Art. 14(2)(c))

All three are submitted simultaneously to the designated coordinating CSIRT and to ENISA via the single reporting platform defined in Article 16. Wardex does not submit anything. Wardex produces the structured artefacts that make submission possible — signed, timestamped, with deadline tracking — and surfaces them to the operator for review and dispatch.

This spec covers exactly what is needed for v2.0: the minimum set of changes that enables a Root client using Wardex to meet Article 14. Article 13 completion, Annex VII documentation output, and Article 28 conformity declaration support are deferred to the roadmap captured in Section 8.

---

## 2. Design Principles

These principles govern every decision in this spec. They are not aspirational — they are constraints.

**Enable, never execute.** Wardex detects, structures, and surfaces. It does not send, submit, or notify on behalf of the operator. No network call is made to any CSIRT, ENISA endpoint, or reporting platform. The operator receives a ready artefact and acts on it.

**Prepare the evidence trail.** Every detection event that could trigger Article 14 obligations is immediately recorded in the gate audit log with a cryptographically chained entry. The chain provides non-repudiation: if an operator is asked when they became aware of a vulnerability, the log answers.

**Deadlines are visible, not enforced.** When an actively exploited vulnerability is detected, Wardex calculates the three Article 14 deadlines from the detection timestamp and displays them prominently. It does not block the pipeline when a deadline passes — that is an operational decision. It does emit a warning on subsequent evaluations if a generated notification artefact has not been marked as dispatched.

**Hard stop on active exploitation.** A vulnerability classified as actively exploited blocks the gate unconditionally, regardless of CVSS score, EPSS value, or existing risk acceptances. Active exploitation is not a risk level — it is a legal state. This is the single new hard stop introduced in v2.0.

**The `ENISABackend` is a stub.** The Article 16 single reporting platform does not yet have a published API. The `Forwarder` interface gains an `ENISABackend` struct that satisfies the interface and logs a structured record, but sends nothing. When the ENISA API is published, the stub is replaced. The operator is informed of the stub status in the CLI output.

---

## 3. Breaking Changes from v1.9.2

v2.0 is a major version bump. The following changes are not backward-compatible.

**New required field in `VulnerabilityEnvelope`.** The envelope gains an `actively_exploited` boolean field. Existing envelopes without this field fail strict validation. In non-strict mode (default), absence is treated as `false` with a `[WARN]` emitted. Pipelines using `wardex convert grype` receive this field automatically from v2.0 onwards via KEV correlation (see Section 5.1).

**Active exploitation hard stop.** Any vulnerability with `actively_exploited: true` causes `wardex evaluate` to exit with code `12` (new: `ActivelyExploited`). Existing risk acceptances do not override this. A new `wardex accept active-exploit` flow (Section 5.3) is the only mechanism to record a temporary acknowledgement — and it does not unblock the gate; it records the operator's awareness for audit purposes.

**Gate audit log entry format extended.** `model.AuditEntry` gains new fields. Existing log entries remain valid; new fields are `omitempty`. Tooling that parses `wardex-gate-audit.log` directly may need updating.

**New exit code `12`.** `pkg/exitcodes` adds `ActivelyExploited = 12`. CI pipelines should handle this explicitly.

---

## 4. New Data Model

### 4.1 `VulnerabilityEnvelope` additions

```go
type VulnerabilityEnvelope struct {
    ConvertedBy     string          `yaml:"converted_by"`
    Vulnerabilities []Vulnerability `yaml:"vulnerabilities"`
    // NEW in v2.0
    EvaluatedAt     time.Time       `yaml:"evaluated_at,omitempty"`
}

type Vulnerability struct {
    // existing fields unchanged
    CVEID           string  `yaml:"cve_id"`
    CVSSScore       float64 `yaml:"cvss_score"`
    EPSSScore       float64 `yaml:"epss_score"`
    Reachable       bool    `yaml:"reachable"`
    // NEW in v2.0
    ActivelyExploited      bool      `yaml:"actively_exploited"`
    ActivelyExploitedSince time.Time `yaml:"actively_exploited_since,omitempty"`
    ExploitedSource        string    `yaml:"exploited_source,omitempty"`
    // e.g. "cisa-kev", "manual", "brimmed-hat"
}
```

`ActivelyExploitedSince` records when the exploitation was first confirmed — distinct from when Wardex detected it. `ExploitedSource` traces the origin of the classification, which feeds the Article 14(2)(b) "information about any malicious actor" field when available.

### 4.2 `AuditEntry` additions

```go
type AuditEntry struct {
    // existing fields unchanged
    Timestamp      time.Time `json:"timestamp"`
    ConfigHash     string    `json:"config_hash"`
    EvidenceHash   string    `json:"evidence_hash,omitempty"`
    OverallDecision string   `json:"overall_decision,omitempty"`
    RiskScore      float64   `json:"risk_score,omitempty"`
    Detail         string    `json:"detail,omitempty"`
    // NEW in v2.0
    PreviousEntryHash   string              `json:"previous_entry_hash,omitempty"`
    ActivelyExploited   []string            `json:"actively_exploited_cves,omitempty"`
    Art14DeadlineEarlyWarning time.Time     `json:"art14_deadline_early_warning,omitempty"`
    Art14DeadlineNotification time.Time     `json:"art14_deadline_notification,omitempty"`
    Art14NotificationArtefactPath string    `json:"art14_notification_artefact_path,omitempty"`
}
```

`PreviousEntryHash` implements the cryptographic chaining deferred from v1.9.2. Each entry hashes the previous entry's raw JSONL bytes using SHA-256. A gap in the chain is detectable and reported by `wardex accept verify-forwarding`.

### 4.3 `Art14NotificationArtefact`

New type. Written to disk when active exploitation is detected. Never sent by Wardex.

```go
type Art14NotificationArtefact struct {
    // Metadata
    ArtefactID      string    `json:"artefact_id"`       // UUID v4
    GeneratedAt     time.Time `json:"generated_at"`
    GeneratedBy     string    `json:"generated_by"`      // "wardex/v2.0.0"
    WardexActor     string    `json:"wardex_actor"`      // WARDEX_ACTOR env var
    Status          string    `json:"status"`            // "draft" | "dispatched"

    // Article 14(2)(a) — Early Warning fields
    EarlyWarning struct {
        AwarenessTimestamp time.Time `json:"awareness_timestamp"`
        Deadline           time.Time `json:"deadline"`           // +24h
        AffectedStates     []string  `json:"affected_states,omitempty"`
    } `json:"early_warning"`

    // Article 14(2)(b) — Vulnerability Notification fields
    Notification struct {
        Deadline             time.Time `json:"deadline"`           // +72h
        ProductName          string    `json:"product_name"`
        ProductVersion       string    `json:"product_version"`
        CVEIDs               []string  `json:"cve_ids"`
        ExploitationNature   string    `json:"exploitation_nature"`  // free text
        VulnerabilityNature  string    `json:"vulnerability_nature"` // free text
        CorrectiveMeasures   string    `json:"corrective_measures,omitempty"`
        UserMitigations      string    `json:"user_mitigations,omitempty"`
        SensitivityFlag      bool      `json:"sensitivity_flag"`
    } `json:"notification"`

    // Article 14(2)(c) — Final Report fields (populated when patch is available)
    FinalReport struct {
        Deadline             time.Time `json:"deadline,omitempty"`  // patch_date + 14d
        PatchAvailableAt     time.Time `json:"patch_available_at,omitempty"`
        VulnerabilityDescription string `json:"vulnerability_description,omitempty"`
        Severity             string    `json:"severity,omitempty"`
        Impact               string    `json:"impact,omitempty"`
        ThreatActorInfo      string    `json:"threat_actor_info,omitempty"`
        SecurityUpdateDetails string   `json:"security_update_details,omitempty"`
    } `json:"final_report,omitempty"`

    // Integrity
    HMAC string `json:"hmac"` // HMAC-SHA256 over canonical JSON of above fields
}
```

Fields that the operator must complete before dispatch are left as empty strings or zero times. Wardex populates what it knows from the evidence envelope and audit log; the operator fills the rest.

---

## 5. New Behaviours

### 5.1 KEV Correlation in `wardex convert`

The CISA Known Exploited Vulnerabilities catalogue is the primary authoritative source for `actively_exploited` classification. It is a static JSON file published at `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` and updated continuously.

`wardex convert` gains a `--kev` flag accepting a local path to a downloaded KEV catalogue snapshot:

```bash
wardex convert grype grype-output.json --kev kev-catalogue.json
```

For each CVE in the Grype output, Wardex checks presence in the KEV catalogue. If found, `actively_exploited: true` is set, `exploited_source: "cisa-kev"` is populated, and `actively_exploited_since` is set to the KEV `dateAdded` field.

Wardex does not download the KEV catalogue. This is consistent with the enable-never-execute principle: the operator fetches the catalogue (a one-line curl), Wardex correlates. A helper note in the CLI output reminds the operator of the download command when `--kev` is not supplied.

The Brimmed Hat CTI feed, when available, can also produce a KEV-compatible JSON as its output format, allowing the same `--kev` flag to consume it without any code change.

### 5.2 Active Exploitation Hard Stop in `wardex evaluate`

When any vulnerability in the envelope has `actively_exploited: true`, `wardex evaluate` does the following in sequence:

1. Records a chained `AuditEntry` with `actively_exploited_cves` populated and all three Article 14 deadlines calculated from `time.Now()` as the awareness timestamp.
2. Generates an `Art14NotificationArtefact` in draft status, writes it to `wardex-art14-{artefact_id}.json` in the working directory (configurable via `--art14-output-dir`).
3. Prints a structured `[BLOCK]` output identifying each actively exploited CVE, the three deadlines in human-readable and ISO 8601 format, and the path to the generated artefact.
4. Exits with code `12`.

The awareness timestamp used for deadline calculation is `time.Now()` unless `actively_exploited_since` is set in the envelope and is earlier, in which case that value is used. This matters: if an operator runs Wardex two days after a KEV entry was added, the 24h deadline has already passed, and Wardex says so explicitly.

### 5.3 `wardex accept active-exploit`

A risk acceptance does not unblock an actively exploited vulnerability. This is a deliberate hard constraint — no operator action within Wardex removes the gate block for an actively exploited CVE.

The `wardex accept active-exploit` subcommand exists for a different purpose: to record, in the HMAC-signed audit log, that the operator is aware of the active exploitation and has made a specific documented decision. This record is evidence for the Article 14 audit trail.

```bash
wardex accept active-exploit \
  --cve CVE-2024-3094 \
  --justification "Mitigated by network isolation. Patch in progress. Art14 notification dispatched." \
  --art14-artefact wardex-art14-abc123.json
```

The `--art14-artefact` flag links the acceptance record to the notification artefact by path and HMAC. This creates a traceable chain: detection → artefact generated → operator acknowledged → (operator dispatches externally). The gate remains blocked. Exit code remains `12`.

### 5.4 `wardex art14` — Artefact Lifecycle Management

New top-level subcommand for managing notification artefacts.

```
wardex art14 list                         # list all artefacts in working dir
wardex art14 show <artefact-id>           # print artefact as formatted JSON
wardex art14 mark-dispatched <artefact-id> --phase early-warning|notification|final-report
wardex art14 finalize <artefact-id>       # populate final-report fields interactively
wardex art14 verify <artefact-id>         # verify HMAC integrity
```

`mark-dispatched` updates the artefact `status` field and appends a dispatch record to the gate audit log, but performs no network operation. The operator has dispatched externally; this command records that fact.

`finalize` opens the artefact for editing of the `final_report` block, re-signs the HMAC, and writes the updated file. It does not send anything.

### 5.5 `ENISABackend` (stub)

`pkg/accept/forward.go` gains a new backend:

```go
type ENISABackend struct {
    // stub — no network configuration, no credentials
}

func (e *ENISABackend) Forward(entry AuditEntry) error {
    // Logs the entry to a local file wardex-enisa-queue.jsonl
    // Does not make any network connection.
    // Emits [INFO] ENISA reporting platform API not yet published.
    // Artefact queued locally at wardex-enisa-queue.jsonl.
    return nil
}
```

The backend is configured in `wardex-config.yaml` as `forward: ["enisa"]`. Its presence in configuration triggers a startup notice:

```
[INFO] ENISABackend is a stub. No data will be transmitted.
       Queue path: wardex-enisa-queue.jsonl
       When the ENISA single reporting platform API is published,
       update Wardex and configure ENISABackend.endpoint.
```

This makes the stub visible — an operator cannot accidentally believe notifications are being sent.

---

## 6. Configuration Changes

New block in `wardex-config.yaml`:

```yaml
cra:
  art14:
    output_dir: "."                    # where artefact JSON files are written
    awareness_source: "detection"      # "detection" | "envelope"
    # "detection": awareness timestamp = time.Now() at evaluate time
    # "envelope":  awareness timestamp = actively_exploited_since from envelope (if set)
    product_name: ""                   # populated in artefact; operator fills if empty
    product_version: ""                # same
    kev_path: ""                       # default KEV catalogue path for wardex evaluate
                                       # (avoids requiring --kev flag every time)

reporting:
  gate_log:
    path: wardex-gate-audit.log
    forward: ["syslog"]               # existing
    on_fail: warn
  enisa_queue:
    path: wardex-enisa-queue.jsonl    # NEW — ENISABackend queue file
```

The `cra.art14.product_name` and `cra.art14.product_version` fields pre-populate the notification artefact. If empty, Wardex writes `"[OPERATOR: complete before dispatch]"` as the field value — explicit and visible.

---

## 7. Exit Codes

Updated `pkg/exitcodes`:

```go
const (
    OK              = 0
    GateBlocked     = 10   // existing
    ComplianceFail  = 11   // existing
    IntegrityFail   = 3    // existing
    ActivelyExploited = 12 // NEW — one or more CVEs classified as actively exploited
)
```

CI pipelines should treat exit code `12` as distinct from `10`. A gate block (10) may be resolved by a risk acceptance. An active exploitation block (12) cannot.

---

## 8. Deferred Roadmap

The following items are explicitly out of scope for v2.0 and are captured here to avoid scope creep during implementation.

**v2.1 — Article 13 completion.** Support period field with justification (`cra.support_period`), VDP reference field, and SBOM presence validation as a soft compliance check (warning, not hard stop — the hard stop arrives when Art. 13 full application date approaches in December 2027).

**v2.2 — Annex VII documentation output.** `wardex report annex7` generates a structured Markdown or JSON document covering the Annex VII checklist fields that Wardex can populate from its inputs and audit log.

**v2.3 — `--strict` field validation for end users.** Deferred from v1.9.1. Applies `KnownFields(true)` to operator-supplied `wardex-config.yaml` in production pipelines.

**v2.x — `data_class` scoring.** Re-introduction of `model.AssetContext.DataClass` with proper scoring semantics, deferred from v1.9.1.

**v2.x — ENISABackend real implementation.** Blocked on ENISA publishing the Article 16 single reporting platform API. When published, `ENISABackend` is updated to make authenticated POST requests using the specified format. This is a targeted change to a single file.

**v3.0 — Article 28 conformity declaration support.** Generating the EU Declaration of Conformity template populated from Wardex inputs. Significant scope; separate spec required.

---

## 9. Testing Requirements

Each new behaviour requires tests before merge.

`cmd/evaluate/evaluate_active_exploit_test.go` — hard stop triggers on `actively_exploited: true`; exit code is `12`; artefact is written; audit entry is chained correctly; deadlines are calculated correctly for both `detection` and `envelope` awareness sources; existing risk acceptances do not override the block.

`cmd/convert/convert_kev_test.go` — KEV correlation sets fields correctly; CVEs absent from KEV are not marked exploited; `actively_exploited_since` is populated from KEV `dateAdded`; missing `--kev` flag emits helper note, not error.

`cmd/art14/art14_test.go` — `mark-dispatched` updates status and appends audit entry; `verify` detects HMAC tampering; `finalize` re-signs correctly; `list` shows only artefacts in the configured output dir.

`pkg/accept/forward_enisa_test.go` — `ENISABackend.Forward` writes to queue file, makes no network connection, returns nil error.

`model/audit_chain_test.go` — chain verification detects a gap (missing entry); chain verification detects tampering (modified entry); first entry in a new log has empty `previous_entry_hash`.

Coverage gate remains at 70% minimum.

---

## 10. Open Questions

**OQ-01 — KEV update frequency.** The operator downloads the KEV catalogue manually. Should `wardex convert` warn if the catalogue file is older than N days? Proposed: warn if mtime > 7 days. Configurable via `cra.art14.kev_max_age_days`. Decision deferred to implementation.

**OQ-02 — Artefact storage.** Artefacts written to the working directory may be lost in ephemeral CI environments. Should the ENISABackend queue file and artefacts be written to a configurable persistent path by default? Current default is `.` (working dir). Operators running in CI should set `cra.art14.output_dir` to a mounted volume. No change to default for now — consistent with Wardex's existing behaviour for audit logs.

**OQ-03 — Multiple actively exploited CVEs in one evaluation.** The spec treats all actively exploited CVEs in a single envelope as producing one artefact with multiple CVE IDs in `notification.cve_ids`. This is the simpler implementation. If regulators interpret Article 14 as requiring one notification per CVE, the artefact generation logic needs to change. Proceed with one artefact per evaluation for now; revisit if ENISA guidance specifies otherwise.

**OQ-04 — `wardex accept active-exploit` and gate unblocking.** The current position is firm: no acceptance unblocks an active exploitation. If a client scenario genuinely requires a temporary unblock (e.g., the CVE is in a component that is being removed and the pipeline must run to deploy the removal), a separate `--emergency-override` flag with a mandatory justification and CISO-level trust requirement could be considered. Not in v2.0.
