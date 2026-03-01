## Wardex v1.4.0 (System Features Sprint)

This release focuses on hardening enterprise telemetry, improving the observability of risk thresholds, and introducing native false-positive suppression via VEX.

### Added
- **SIEM Forwarding Verification**: Added the `wardex accept verify-forwarding` command to validate that local audit trails (`wardex-accept-audit.log`) are healthy and formatted correctly for remote SIEM ingestion agents.
- **`WARN` Gate Threshold Observable Context**: The release gate now explicitly surfaces the `[!] WARN` tag and exits cleanly (`0`) when an evaluated pipeline risk falls between the `warn_above` and `risk_appetite` boundaries. This provides critical observability without hard-blocking pipelines unnecessarily.
- **Configurable Snapshot File Path**: Replaced the hardcoded `.wardex_snapshot.json` tracker. Monorepo pipelines can now use the `--snapshot-file` flag to securely isolate their gap analysis states and delta reports.
- **VEX Suppressions**: The native CycloneDX SBOM importer natively parses the `analysis` object. SBOM Vulnerability components with a VEX state of `false_positive` or `not_affected` are automatically bypassed by the risk engine, instantly reducing noisy false alarms.
