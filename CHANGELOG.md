# Changelog

All notable changes to this project will be documented in this file.

and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.2] — 2026-06-29

### Security

- **CI-1 — Supply chain fix (release.yml)**: Syft installation replaced `curl | bash` with pinned binary download + SHA-256 checksum verification. Hash displayed in CI logs for PR diff visibility. ([PR #96](https://github.com/had-nu/wardex/pull/96))
- **CI-2 — Unsigned dev images (docker.yml)**: Branch-triggered Docker images now use `dev-` namespace prefix and are signed immediately with cosign (removed tag-only gate). ([PR #97](https://github.com/had-nu/wardex/pull/97))
- **CI-3 — Path traversal via symlink bypass**: Replaced `utils.SafePath` with `cli.ValidateInputPath`/`cli.ValidateOutputPath` using `filepath.EvalSymlinks` before containment check. Migrated 33 call sites across 19+ files. Fixed TOCTOU in `pkg/accept/accept.go` (validated path used for writes). Fixed gap in `cmd/evaluate/evaluate.go` (`--out-file` now validates before `os.Create`). 33 tests including symlink escape, null bytes, shell injection, pseudo-filesystems. ([PR #98](https://github.com/had-nu/wardex/pull/98))
- **New `pkg/cli/pathguard.go`**: Central path validation package with `ValidateInputPath` (file reads) and `ValidateOutputPath` (file writes). Resolves symlinks via `filepath.EvalSymlinks` before containment check. Accepts `fs.ErrNotExist` for output paths (file not yet created). Checks pseudo-filesystems (`/proc/`, `/sys/`, `/dev/`) in output paths.

## [2.2.0] — 2026-06-25

### Added

- **Configuration Provenance Link (CPL)**: Cryptographic integrity for release gate
  decisions, connecting each evaluation to the configuration in effect at decision time.

- **`wardex config hash`**: Compute SHA-256 or BLAKE3 hash of `wardex-config.yaml` over
  canonicalised content (sorted keys, no comments, normalised whitespace). Deterministic
  across environments — semantically identical configs produce the same hash.
  (`cmd/configseal/hash.go`)

- **`wardex audit verify-link`**: Verify that `config_hash` entries in a wardex audit
  log match the corresponding archived configuration files. Reports `OK`, `MISMATCH`,
  or `MISSING` per entry. Exit code 0 all-OK, 1 on divergence, 2 on error.
  (`cmd/audit/verify_link.go`)

- **`wardex audit verify-chain`**: Validate the integrity of the audit log hash chain.
  Each entry must reference the SHA-256 of the preceding line; first entry must have
  `prev_hash = "genesis"`. Exit code 0 intact, 1 tampered, 2 on error.
  (`cmd/audit/verify_chain.go`)

- **`internal/cpl/` package**: Core CPL library — `ComputeConfigHash` with YAML
  canonicalisation, `VerifyChain` for hash chain integrity, `VerifyLink` for
  config-archive matching. Supports SHA-256 and BLAKE3 with algorithm prefix
  (`sha256:`, `blake3:`). (`internal/cpl/hash.go`, `chain.go`, `verifylink.go`)

- **CPL test suite**: 12 cryptographic integrity tests covering canonicalisation
  determinism, env-var isolation, known vectors, invalid YAML, algorithm prefix
  parsing, mixed-algorithm logs, chain verification (valid, tampered, genesis,
  large corpus), and verify-link (OK, mismatch, missing). (`internal/cpl/*_test.go`)

- **`internal/notification/` package**: Fire-and-forget divergence webhook for CPL.
  Sends HTTP POST with `DivergencePayload` JSON to configurable endpoint. Bearer
  auth via env var, configurable timeout (default 5s, max 30s), non-blocking.
  (`internal/notification/webhook.go`)

- **CPL divergence webhook**: When `wardex audit verify-link` detects MISMATCH or
  MISSING, optionally notifies an external endpoint (SIEM, alerting) without
  affecting exit codes. Configured in `wardex.yaml` under `notifications.divergence_webhook`.

- **`cli_overrides` in audit log**: CLI flags that override config values (e.g.,
  `--gate-mode`, `--fail-above`, `--profile`) are recorded as `cli_overrides` in
  gate audit log entries for full provenance. (`cmd/evaluate/evaluate.go`,
  `pkg/model/audit.go`)

- **Canonicalised ConfigHash**: `accept.ConfigHash()` now uses CPL canonicalisation
  (YAML→JSON→SHA-256) instead of raw byte hashing, ensuring reproducibility across
  formatting differences. (`pkg/accept/accept.go`)

- **Chained audit logging**: All gate evaluation log entries now use
  `ChainedAuditLog` (hash-chain linked) instead of plain `AuditLog`.
  (`cmd/evaluate/evaluate.go`)

- **`--strict` config hash check**: When `wardex evaluate --strict` is active, exit
  code 3 (`IntegrityFailure`) if the config hash cannot be computed.
  (`cmd/evaluate/evaluate.go`)

- **`notifications` config section**: New `wardex.yaml` section for CPL webhook
  configuration (`url`, `auth_env`, `timeout_seconds`, `headers`).
  (`config/config.go`)

- **BLAKE3 support**: Hash algorithm BLAKE3 available via `--algorithm blake3` flag
  on `wardex config hash`. (`internal/cpl/blake3.go`, `go.mod`)

- **CI mirror gate**: CPL integrity check commands documented in the spec for CI
  pipeline integration.

### Changed

- **`pkg/accept.ConfigHash`**: Refactored to delegate to `internal/cpl.ComputeConfigHash`
  with SHA-256 canonicalisation. All callers (evaluate, accept) automatically benefit
  from deterministic hashing.

- **`pkg/model.AuditEntry`**: Added `CliOverrides map[string]string` field for CLI
  provenance tracking.

- **Audit log format**: Gate evaluation entries now use chained logging
  (`ChainedAuditLog`) — each entry carries `previous_entry_hash` for tamper
  detection.

### Security

- **CPL cryptographic integrity**: 12-test suite verifies canonicalisation
  determinism, hash chain integrity, algorithm prefix isolation, and divergence
  detection. Canonicalisation uses `encoding/json` for deterministic key ordering
  (guaranteed since Go 1.12).

---

## [2.1.2] — 2026-06-22

### Added

- **Module path `/v2`**: Module renamed to `github.com/had-nu/wardex/v2`. All SDK imports and `go install` now use the `/v2` path.
- **`pkg/ui/` package**: Wardex lockup SVG (`wardex-lockup.svg`) for branding in documentation and artefacts.
- **Syslog forwarding**: Structured RFC 5424 dispatch of gate decisions, acceptances, and Art14 lifecycle events via `WARDEX_SYSLOG_ENDPOINT` (TCP/UDP/TLS). Opt-in at startup.
- **Syslog stub**: Test double for syslog forwarding without a real server.
- **Dry-run mode**: `wardex evaluate --dry-run` prints what *would* happen without writing artefacts or producing exit codes.
- **`accept verify --output`**: Export verification report as JSON artefact.
- **PKI mode**: Ed25519 CA for certificate-based identity (`wardex pki init`, `wardex pki issue`). Sealed configs carry X.509 chain.
- **Helm chart**: `deploy/helm/wardex/` (v0.1.0, appVersion 2.1.2) — Job, CronJob, KEV init container, PVC, Seccomp, distroless nonroot.
- **docker-compose.yml**: PostgreSQL (audit store), MinIO (artefact bucket), Wardex API stub for local dev.
- **`.github/` PR/issue templates**: Bug report, feature request, pull request templates.
- **Coverage HTML artefact**: CI uploads HTML coverage report as build artefact.
- **Exit code `4` (`Tampered`/`StoreInconsistent`)**: Distinguishes tampered acceptances from store inconsistency.
- **`catalog.Load()` error return**: Callers must now check `([]model.CatalogControl, error)`.
- **`sdk.LoadFramework()` error return**: SDK consumers receive framework load errors.

### Changed

- **CLI refactoring**: 7 `Run` handlers extracted to `cmd/evaluate/cli_handlers.go` (156 → 458 lines). `cli.go` now uses `exitFunc` (mockable), `stderr` (io.Writer), and `acceptCfgPath` global.
- **Evaluate refactoring**: `loadEvalConfig`, `loadEvidence`, `isCI`, `formatDuration` extracted to `cmd/evaluate/evaluate_helpers.go` (615 → 460 inline lines).
- **SDK test coverage**: 46% → 91% (20 new tests across `pkg/sdk/`).
- **CLI test coverage**: 13.3% → 35.8% (13 new execution tests for panic/recover in `pkg/accept/cli/`).
- **CI**: Test scope changed from 10-package list to `./...`, coverage threshold 40%, HTML artefact upload.
- **Lint**: golangci-lint config expanded, `make lint` targets refactored.
- **Flags split** into Core / Advanced groups in `wardex evaluate --help`.

### Fixed

- **`catalog.Load` lack of error checking**: Load errors now propagate to callers.
- **`signer.go` HMAC secret hint**: Clearer message when `WARDEX_ACCEPT_SECRET` is missing.
- **UX hints**: `main.go` adds `[HINT]` messages for common misconfigurations.

### Security

- **GPGSigned merge**: `main` branch commits GPG-signed with key `979AC8CE8F357652`; `commit.gpgsign true` enabled.
- **Distroless nonroot**: Helm chart defaults to `runAsUser: 65532`, read-only root filesystem, all capabilities dropped.

---

## [2.0.1] — 2026-06-10

### Security

- **Weak HMAC fallback removido**: `cmd/evaluate/evaluate.go` agora retorna erro se `WARDEX_ACCEPT_SECRET` não estiver definida, em vez de usar `"REDACTED_WEAK_SECRET_REMOVED"` (CRA-critical).
- **G304 fix — `SafePath` em `pkg/trust/seal.go`**: validação de caminho antes de `os.ReadFile` para evitar path traversal (CRA-critical).
- **SHA pinning do CLA action**: `.github/workflows/cla.yml` usa SHA `ca4a40a7d1004f18d9960b404b97e5f30a505a08` em vez da tag `v2.6.1`.
- **`.github/workflows/ci.yml`**: remoção do `-exclude=G304` global do gosec. Supressões inline em `analyze-gaps.go`, `wexstate.go`, `store.go`, `keyring.go`.
- **`.golangci.yml` expandido**: 9 litters activos (staticcheck, gosec, gomodguard, misspell, exhaustive, unused, errcheck, govet, ineffassign) com configuração v2, 0 issues.
- **`SECURITY.md` actualizado**: contacto real `andre.ataide@proton.me` e PGP fingerprint `979A C8CE 8F35 7652`.
- **`Makefile`**: novo target `make security` (govulncheck + gosec).

### Fixed

- **`exitFunc` mocking em `cmd/art14/art14_test.go`**: `runVerify` com artefacto adulterado já não chama `os.Exit` directamente — usa `exitFunc` mockável, impedindo a morte do test suite.

---

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
