## Wardex v1.5.0 (Framework Expansion Sprint)

This release officially introduces the **Multi-Framework Governance Engine**. Wardex is no longer strictly bound to ISO 27001 reporting.

### Added
- **`--framework` Dynamic Parameter**: A flexible way to scan the same organizational security configurations against different regulatory catalogs. Supported natively out-of-the-box in v1.5.0:
  - `--framework iso27001` (Legacy JSON backwards-compatible default)
  - `--framework soc2` 
  - `--framework nis2` 
  - `--framework dora` 

### Changed
- The entire application core transitioned from an `AnnexAControl` schema abstraction to a globally resilient `CatalogControl` structure.
