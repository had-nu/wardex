# Changelog

All notable changes to this project will be documented in this file.

and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.9.2] — 2026-05-10

## [2.0.0] — 2026-06-10

### Added

- **CRA Article 14 Enablement**: Wardex now generates structured notification artefacts for the EU Cyber Resilience Act Article 14(2) three-phase reporting obligation (early warning, notification, final report).
- **Active Exploitation Hard Stop**: `wardex evaluate` exits with code `12` (`ActivelyExploited`) when any vulnerability is marked `actively_exploited: true`. This hard stop cannot be overridden by risk acceptances.
- **KEV Correlation (`--kev`)**: `wardex convert grype` gains a `--kev` flag that correlates CVEs against the CISA Known Exploited Vulnerabilities catalogue, setting `actively_exploited`, `exploited_source`, and `actively_exploited_since` fields.
- **Audit Chain Integrity**: All gate audit log entries are now cryptographically chained via SHA-256 `previous_entry_hash`. `VerifyChain()` detects tampering and gaps.
- **`wardex art14` Subcommand**: New command for lifecycle management of Article 14 artefacts: `list`, `show`, `mark-dispatched`, `finalize`, `verify`.
- **`wardex accept active-exploit`**: Records operator awareness of active exploitation in the chained audit log for compliance trail evidence.
- **ENISABackend (stub)**: New `enisa` forward backend writes to a local JSONL queue file. No network transmission — awaiting the ENISA Article 16 API publication.
- **Configuration**: New `cra.art14` and `reporting.enisa_queue` blocks in `wardex-config.yaml`.

### Changed

- **BREAKING**: `Version` bumped to `2.0.0`.
- **BREAKING**: `VulnerabilityEnvelope` now has an optional `evaluated_at` field.
- **BREAKING**: `Vulnerability` gains three new optional fields: `actively_exploited`, `actively_exploited_since`, `exploited_source`.
- **BREAKING**: `AuditEntry` gains `previous_entry_hash`, `actively_exploited_cves`, `art14_deadline_early_warning`, `art14_deadline_notification`, `art14_notification_artefact_path`.
- New exit code `12` (`ActivelyExploited`). CI pipelines should handle this explicitly.

### Fixed

- `cmd/art14/art14.go:runVerify` now uses mockable `exitFunc` instead of `os.Exit`, enabling proper tampered-verification testing.

---


### Added

- **Gate Decision Log (G1)**: `wardex evaluate` now records every gate decision in
  `wardex-gate-audit.log` (configurable via `--gate-log`). Entries include config
  hash, evidence hash, overall decision, and risk score.
- **Evidence Provenance (G2)**: New `converted_by` field in evidence envelopes.
  `wardex evaluate` now warns if evidence was not canonicalised via `wardex convert`.
- **Strict Provenance Mode**: `--strict` flag now also enforces canonicalised evidence.
- **Log Forwarding (G3)**: Integrated gate decisions with the `Forwarder` interface.
  Supports real-time dispatch to Syslog via `reporting.gate_log.forward` config.
- **Data Model Extensions**: `model.AuditEntry` extended with `evidence_hash` and
  `overall_decision`; new `model.VulnerabilityEnvelope` for provenance tracking.

### Fixed

- **Schema Gap**: Updated `doc/examples/wardex-config.yaml` to include the new
  `gate_log` block, ensuring compliance with `KnownFields(true)` validation tests.

---

## [1.9.1] — 2026-05-09

### Removed

- `organization` block (`name`, `sector`, `scope`) — never consumed by the scorer
  or by `wardex assess`.
- `domain_weights` map — placeholder for an unshipped feature.
- `control_weights` map — placeholder for an unshipped feature.
- `thresholds` block (`fail_above`, `warn_above`) — duplicated
  `release_gate.warn_above` semantically and was never read. The live failure-on-gap
  flag is `--fail-above` on `wardex evaluate` (CLI), not a YAML field.
- `reporting.verbose` — the CLI flag `--verbose` is the source of truth.
- `release_gate.asset_context.data_class` — declared in `model.AssetContext` but
  never consumed by the scorer (which reads `criticality`, `internet_facing`,
  `requires_auth`, `environment`). Re-introduction with proper scoring semantics
  is deferred to v1.10.x.

### Fixed

- `doc/examples/wardex-config.yaml` rewritten with fields verified against the live
  structs. The previous file in v1.9.0 used a `thresholds:` block with non-existent
  keys; the rewrite mirrors `Config`, `model.AssetContext`, and
  `model.CompensatingControl` exactly.
- `test/testdata/wardex-config.yaml`: `compensating_controls` now uses the correct
  fields (`type`/`effectiveness`/`justification` instead of `id`/`name`/`reduction`);
  `data_classification:` removed (the field was orphan and the spelling was wrong
  for `AssetContext` anyway).

### Added

- `config/config_examples_test.go` (`TestPublishedExamplesMatchSchema`) — strict
  schema validation of `doc/examples/wardex-config.yaml` and
  `test/testdata/wardex-config.yaml` using `yaml.Decoder.KnownFields(true)`. CI
  blocks any release where a published example diverges from the live schema.

### Compatibility

YAML files written for v1.9.0 with the now-removed blocks continue to load without
error in production code paths. The runtime `Load()` continues to accept unknown
fields (Go YAML decoder default) to preserve backward compatibility. No migration
script required.

---

## [1.9.0] - 2026-05-08

### Added
- **Wardex Trust Store**: New cryptographic governance layer for release gate configurations.
- **Sealed Config (`wardex.wexstate`)**: Support for signing and verifying configuration integrity.
- **Key Management**: `wardex keygen` for operator keypairs (ed25519).
- **Trust Commands**: `wardex trust` (init, add, revoke) to manage authorized actors and roles.
- **RBAC for Profiles**: `allowed_actors` field to restrict profile usage to specific identities.
- **Signed EPSS Enrichment**: Verification of exploit probability data signatures.
- **Remote Trust Store**: Support for fetching `wardex-trust.yaml` from remote URLs.

### Changed
- CLI banner redesign.
- Updated exit codes: `3` for integrity failure, `10` for gate block, `11` for compliance failure.

---

## [1.8.1] - 2026-05-07

### Fixed
- **Build Issue**: Fixed `go:embed` path for `wardex-risk-simulator.jsx` in `test/embed.go`.

---

## [1.8.0] - 2026-04-24

### Added
- **Orchestration Command (`wardex assess`)**: A unified command for multi-layer compliance and asset-based assessment.
- **Layer Delta Analysis**: Automatic identification of "Paper Security" (documented only) and "Shadow Security" (implemented only).
- **Asset Compliance Models**: Context-aware scoring for individual business systems (Criticality, Exposure, Threats).
- **Risk-Based Scoring v2**: New roadmap prioritization formula incorporating `ContextWeight` and `Effectiveness`.
- **Flexible Ingestion**: Support for root-level lists in YAML/JSON control and asset definitions.

### Changed
- **BREAKING: Architectural Flattening**: Consolidated `pkg/accept` into a unified high-performance package.
- **Coverage Strictness**: The global coverage metric now requires the `implemented` layer for a `Covered` status.
- **Documentation Overhaul**: Updated Playbook and Technical View for the RPO Platform transition.
- **Cleanup**: Purged legacy PoCs and non-essential artifacts; reorganized research data.

### Fixed
- **Deduplication Logic**: `LoadMany` now correctly handles same-ID controls across different layers (ID|Layer).
- **Model Inconsistency**: Updated `Asset` schema to support advanced exposure context and threat scenarios.

---

## [1.7.2] - 2026-04-21

### Added
- **SDK API**: New programmatic API for integration (`pkg/sdk/assess.go`)
- **NIS2/DORA Support**: Policy templates for NIS2 and DORA frameworks
- **Calibrated Risk Gate**: Enhanced calibration with NAICS organizational profiles
- **Playbook Documentation**: Comprehensive operational playbook
- **Comprehensive USECASES.md**: 10 didactic scenarios for training

### Changed
- Updated Go dependencies (AWS SDK v2, Cloud Logging)
- GitHub Actions updated to latest versions
- Improved documentation and CLI banner redesign
- Enhanced risk calibration with statistical bootstrapping

### Fixed
- Fixed `.golangci.yml` configuration (v2 → v3 format)
- StaticCheck QF1003 resolved (if/else → switch)
- Various README typos and linter configurations

### Security
- Isolated empirical research scripts to `/research`
- Internal docs moved to `/internal/doc/` for cleaner public clone

---
... [rest of the file remains unchanged]
