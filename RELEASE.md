## Wardex v1.3.0 (Enterprise Compliance Release)

This release focuses on enterprise-grade compliance, introducing native SBOM ingestion, dynamic Role-Based Access Control (RBAC) profiling, and a mathematically verifiable cryptographic audit trail for risk exceptions.

### Added
- **Native SBOM Ingestion**: Wardex now natively ingests and parses Software Bill of Materials. Using `wardex convert sbom`, pipelines can instantly parse `CycloneDX` and `SPDX` JSON files, extracting CVSS vulnerabilities agnostically without relying on third-party security scanners.
- **RBAC Configuration Profiles (`--profile`)**: Risk thresholds no longer need to be hardcoded globally. The `wardex-config.yaml` now supports a `profiles:` block, allowing different teams (e.g., `frontend`, `backend`, `pci-dss`) to be dynamically invoked at runtime via the `--profile <name>` flag to enforce distinct `risk_appetite` and `warn_above` thresholds.
- **Cryptographic Acceptances Audit**: The Risk Acceptance subsystem has been fortified with HMAC-SHA256 signatures (`pkg/accept/signer`). Exceptions are now completely tamper-evident, immune to timing side-channel attacks via constant-time verification, and strictly bound to the exact point-in-time compliance report to prevent cross-context replay attacks.

### Changed
- **Scenario Proof of Concepts**: Expanded `test/poc/run-all-scenarios.sh` to include complex end-to-end integration tests for SBOM conversions and RBAC profile overriding simulations, ensuring zero regressions on the security gate logic.
