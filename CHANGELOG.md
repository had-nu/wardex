# Changelog

All notable changes to this project will be documented in this file.

and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.0] - 2026-03-01

### Added
- **Real SIEM Telemetry Verification**: Upgraded `verify-forwarding` to use verified TCP/HTTP connection checks with real drop statuses (`exit 1`) to ensure SLA observability for Splunk/Datadog forwarders (G-07).
- **True RBAC Context Enforcement**: `--profile` usage is now verified against an `AllowedActors` array evaluated directly from continuous integration identity (`WARDEX_ACTOR` or `GITHUB_ACTOR`). Any profile mismatches block overrides and enforce the strictest baselines (G-15).
- **Audit-Ready Architecture Strategy**: Added comprehensive documentation on Risk Gate cryptographic non-repudiation and non-repudiation controls. Essential for SOC 2 Type II and ISO 27001 readiness. Wardex now legally protects commercial integration via an enhanced AGPL-3.0 and Commercial dual-license strategy protected by automated CLA rules (G-20, G-21).

## [1.5.0] - 2026-03-01

### Added

- **Multi-Framework Governance Engine**: Substantial architectural expansion natively transforming Wardex from an ISO 27001-only tool into a multi-framework engine.
- **`--framework` Flag**: A new root flag allowing dynamic policy checking. Replaces the hardcoded Annex A library. Supports:
  - `--framework iso27001` (Default)
  - `--framework soc2` (COSO / Trust Services Criteria constraints)
  - `--framework nis2` (EU Directive 2022/2555 cybersecurity objectives)
  - `--framework dora` (Digital Operational Resilience Act ICT risk management)

### Changed
- Abstracted `model.AnnexAControl` schema components functionally into `model.CatalogControl` across `pkg/catalog/` and metrics engines to serve generalized mappings. Backward compatibility for generated `JSON` historical reports is robust.

## [1.4.0] - 2026-03-01

### Added

- **SIEM Forwarding Verification**: Added `wardex accept verify-forwarding` command to validate that local audit trails (`wardex-accept-audit.log`) are healthy and formatted correctly for remote SIEM ingestion agents like Splunk or Datadog.
- **`WARN` Gate Threshold Observable Context**: The gate now explicitly surfaces the `[!] WARN` tag and `exit 0` output naturally when an evaluated pipeline risk falls between the `warn_above` and `risk_appetite` thresholds.
- **Configurable Snapshot File Path**: Replaced the hardcoded `.wardex_snapshot.json` tracker. Monorepo pipelines can now use the `--snapshot-file` flag to securely isolate their gap analysis states.
- **VEX Suppressions**: The CycloneDX SBOM importer natively parses the `analysis` object. Components with a state of `false_positive` or `not_affected` are automatically safely bypassed by the engine, preventing false alarms.

## [1.3.0] - 2026-03-01

### Added

- **Native SBOM Ingestion**: `wardex convert sbom` directly parses CycloneDX and SPDX JSON files into Wardex's native YAML format.
- **RBAC Capabilities**: Added the `--profile` flag to dynamically switch Risk Appetite and Warn Above thresholds per-team.
- **Cryptographic Signatures**: Integrated HMAC-SHA256 signatures to ensure Risk Acceptances are immune to tampering and replay attacks (`pkg/accept/signer`).

### Changed

- Expanded PoC scenarios to include SBOM ingestion and exact threshold blocking simulations.
## [1.2.0] - 2026-03-01

### Added

- **Interactive Risk Simulator**: Added `wardex simulate` to instantly spin up an offline web dashboard.

- **Grype Converter**: Added `wardex convert grype` to natively transform Grype JSON vulnerability scanner output into Wardex natively.

- **`WARN` Risk Band**: Added the `warn_above` configuration threshold.

- **JSON & CSV Export for Acceptances**: The `wardex accept list` command now supports `--output json` and `--output csv`.

- **Configurable Roadmap Limit**: Removed the hardcoded 10-item limit for the maturity roadmap via `--roadmap-limit`.

- **SDK Documentation**: Fully annotated the `pkg/` directories with standard GoDoc API references.

- **Dynamic Versioning**: Added the `--version` flag, and the ASCII banner now prints the dynamically injected build version.


### Changed

- Refactored codebase to abolish emojis and use cleaner ASCII tags (`[PASS]`, `[FAIL]`, `[INFO]`, `[WARN]`).

- Cleaned up overly verbose inline tutorial comments from core files.

- Improved validation of banned justification phrases to catch them anywhere within a sentence.



## [1.1.1] - 2026-03-01
### Fixed
- **G-01**: `time.ParseDuration` day syntax: Added `pkg/duration` with `ParseExtended()` to support `d` suffix (`30d`, `3d`). Fixed bugs in `--expires` and `--warn-before` flags.
- **G-02**: Config propagation: Fixed `wardex accept` subcommands ignoring the `--config` flag by passing configuration correctly from the root command.
- **G-03**: Multi-CVE acceptance: Refactored request handler to create 1 distinct acceptance record per CVE passed via repeatable `--cve` flags, instead of silently discarding all but the first.
- **G-04**: Exit codes: Replaced POSIX-conflicting magic exit codes (like `os.Exit(2)`) with a dedicated `pkg/exitcodes` package containing semantic named constants (`GateBlocked=10`, `ComplianceFail=11`, etc.).

### Changed
- Changed default `--warn-before` for expirations from `"3d"` to `"72h"` as a safer fallback.

## [1.1.0] - 2026-02-28
### Added
- **Risk Acceptance Engine**: New `wardex accept` subcommands (`request`, `list`, `verify`, `revoke`, `check-expiry`) to handle formalized acceptances for gate-blocked releases.
- **Cryptography & Integrity**: Added HMAC-SHA256 signatures, `JSONL` append-only audit logs, and configuration drift detection for exceptions.
- **POC**: Fixed end-to-end Proof of Concept with 4 validated scenarios and documentation.
- Comprehensive technical documentation and specifications for the new risk acceptance capabilities.
- Localized READMEs (English, Spanish, French, Portuguese) with new badges and headers.

### Fixed
- `gosec` G304 and G302 file permission issues (updated to 0750/0600).
- Misspell typos across the codebase.
- Unchecked errors reported by linters.
