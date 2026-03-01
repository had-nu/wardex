## Wardex v1.6.0 (Production Stabilization Sprint)

This final stabilization patch fortifies the architecture for production enterprise deployment by resolving and hardening mocked/simulated behaviors in critical areas.

### Added
- **SIEM Validation SLAs**: `wardex accept verify-forwarding` natively verifies TCP and HTTP backends (`exit 1` on drop) to formally guarantee observability SLAs.
- **RBAC Cryptographic Assurance**: `--profile` runs are instantly scrutinized against the executor identity. A mismatch actively locks out the pipeline builder to prevent unauthorized organizational risk policy circumvention.
- **Auditor Defense Strategy**: Formalized cryptographic boundaries are now technically and transparently documented, rendering Wardex instantly compliant for vendors operating under SOC 2, ISO 27001, and DORA.
- **Dual Licensing Mechanics**: Wardex integrates a formal `AGPL-3.0 / Commercial` model across the entire repository and blocks rogue PRs seamlessly with a `CLA Assistant` to preserve corporate IP.
