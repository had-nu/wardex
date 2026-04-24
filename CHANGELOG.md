# Changelog

All notable changes to this project will be documented in this file.

and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
