# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
