## Wardex v1.2.0 (Developer Adoption Release)

This release focuses on dramatically reducing integration friction, enhancing the developer experience, and introducing the much-requested `WARN` risk band for more flexible CI/CD pipelines.

### Added
- **Interactive Risk Simulator**: Added `wardex simulate` to instantly spin up an offline web dashboard. This allows teams to visually test how CVSS, EPSS, and compensating controls affect their overall risk score in real-time.
- **Grype Converter**: Added `wardex convert grype` to natively transform Grype JSON vulnerability scanner output into Wardex's native YAML format for seamless pipeline integration.
- **`WARN` Risk Band**: Added the `warn_above` configuration threshold. The gate now supports an intermediate band where releases can proceed (with strong warnings) if they exceed `warn_above` but haven't breached the fatal `risk_appetite`.
- **JSON & CSV Export for Acceptances**: The `wardex accept list` command now supports `--output json` and `--output csv` flags for programmatic parsing.
- **Configurable Roadmap Limit**: Removed the hardcoded 10-item limit for the maturity roadmap. You can now control the report length natively using the `--roadmap-limit` flag.
- **SDK Documentation**: Fully annotated the `pkg/` directories with standard GoDoc API references, unlocking native programmatic integrations.
- **Dynamic Versioning**: Added the `--version` flag, and the ASCII banner now prints the dynamically injected build version.

### Changed
- Refactored codebase to abolish emojis and use cleaner ASCII tags (`[PASS]`, `[FAIL]`, `[INFO]`, `[WARN]`).
- Cleaned up overly verbose inline tutorial comments from core files (`main.go`, `grype.go`, `scorer.go`, `test/poc/main.go`) for a more professional, SDK-ready codebase.
- Improved validation of banned justification phrases to catch them anywhere within a sentence, rather than requiring an exact string match.
