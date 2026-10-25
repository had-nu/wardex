# SPEC-M1 — Contracts and kit: the shared base

Wardex · draft 0.2 · 20 October 2026 · base: baseline/modular-0 (measurements at main @ a75500b)

## 1. Purpose

Module 1 creates the base on which every other module depends: `contracts` (pure types) and `kit` (primitives). It also fixes the output contract (`schema_version` and opt-in JSON v2) and the error model (exit codes and `Diagnostic`).

The measurement changed the design. `pkg/model` is not a shared core: of its 37 types, only 3 need to rise to `contracts`. `Decision` has consumers in three modules; `AssetContext` and `CompensatingControl` rise because the shared `Config` uses them. By D2, `contracts` stays deliberately small, and the other 34 types move to their owning modules (M2, M3 and M4).

## 2. Scope

**In:** create `pkg/contracts` and `pkg/kit`; move there what has at least two module consumers; split `config`; remove the triplicated CBOR initialisation; add `Diagnostic`, `schema` and `exitcodes.FromError`; add the `--json-version` flag to `assess`.

**Out:** moving the owners' types (M2 to M4); converting the 12 `ui.*` sites (each owning module converts its own); JSON v2 for other commands; `kit/reportio` and `kit/canonicalhash` (M2 to M5); new `config` validation (D5); the decision on exit code 2 (M5).

## 3. Inherited decisions

Global decisions that apply: D2 (layout, two-consumer rule, `config` split), D3 (opt-in JSON v2), D4 (`Diagnostic` and errors), D5 (moving is not mixed with adding), D7 (`/v3` path, before M1) and D10 (merge at the end of the module).

| # | Module decision (mandatory) |
| --- | --- |
| M1-D1 | `M0#R1` reads «`contracts` imports no repository packages outside `pkg/contracts/...`»: subpackages of `contracts` import each other. The same reading applies to `kit` with `pkg/kit/...` plus `contracts`. The M0 manifest must be updated accordingly. |
| M1-D2 | Types with consumers in more than one module move up to `contracts` (the facade and the adapters do not count, because they use the owner's public API), together with the types that a type already in `contracts` depends on: `Decision` (assess, gate and integrity), and `AssetContext` and `CompensatingControl`, which the shared `Config` uses and which `contracts` cannot import from the gate. |
| M1-D3 | `pkg/duration` and `pkg/utils` do not move up: each has one consumer (`accept/cli` and `orchestrator/gate.go`). They stay with the gate. |
| M1-D4 | `ApplyProfile` keeps the injected `io.Writer` and does not become a `Diagnostic`: it is a security warning written to a destination the caller chooses, and the text must remain byte-for-byte identical. |
| M1-D5 | JSON v2 is produced by a reflection encoder in `contracts/schema`, which gives snake_case names to fields without a tag and leaves map keys untouched. Rejected: a token post-processor (it corrupts data keys) and per-module DTOs (they duplicate types and drift). |
| M1-D6 | JSON v2 includes `diagnostics` (always present, possibly empty); v1 does not change. |
| M1-D7 | `--json-version` exists only in commands that support v2. In M1 only `assess`; in the others, the unknown flag fails as today. |
| M1-D8 | The module is delivered in two phases on the same branch, in separate commits: M1a moves only (identical golden) and M1b adds only. |
| M1-D9 | `Diagnostic` codes: `<module>.<theme>.<cause>`, lowercase, stable once published. |

## 4. Prerequisites

- M0 closed (`baseline/modular-0`), with the golden harness, the boundary guard, the floors and `check-specs` in CI. Status on 20 October: the tag does not exist.
- The mechanical `/v3` path PR (`M0#D7`) merged: the imports below already use `github.com/had-nu/wardex/v3/...`. Status: not merged.
- `v2.7.0-rc.1` published (the baseline for the golden tests). Status: not published.
- The work in progress in `config/config.go` and `internal/policy/loader.go` (B1 and C1, `M0#D8`) is merged into rc.1 before M1 moves `config`.
- This spec may be discussed earlier; implementation starts only after the points above.

At the time of this draft the working tree is on `release/2.7.0`: `go.mod` still declares `/v2`, the `baseline/modular-0` tag does not exist, and the golden harness and the boundary guard are not in the tree. The prerequisites are a gate, not a formality.

## 5. Components

| Field | Value |
| --- | --- |
| Inputs | `pkg/exitcodes`, `pkg/cli`, `pkg/atomicwrite`, `config/`, 3 types from `pkg/model`, 3 CBOR initialisations (`attest`, `trust`, `internal/cpl`) |
| Outputs | `pkg/contracts` (root, `exitcodes`, `config`, `diag`, `schema`), `pkg/kit` (`safeio`, `atomicwrite`, `configio`, `cborcanon`), `ui.RenderDiagnostics`, the `--json-version` flag in `assess` |
| Public API | Everything in `pkg/contracts/...` and `pkg/kit/...` (sections 5.2 and 5.3) |
| Allowed dependencies | `contracts`: standard library. `kit`: standard library, `gopkg.in/yaml.v3`, the CBOR library already in use, and `contracts` |
| Absorbed packages | `pkg/exitcodes`, `pkg/cli` (becomes `safeio`), `pkg/atomicwrite`, `config`; 3 types from `pkg/model` |
| Absorbed commands | None (only the flag in `assess`) |
| Branch | `mod/1-contracts` |
| Estimate | M1a 2 to 3 days, M1b 2 to 3 days (mine, to validate; the 19 October review gave 3 to 4 days for the whole M1, including the `/v3` work, which is now a separate PR) |

### 5.1 What `pkg/model` actually is

The measurement records, for each of the 37 types, which target modules use it outside `model`. The facade and the adapters do not count as consumers.

| Owner | Types | When it leaves `model` |
| --- | --- | --- |
| `contracts` (3) | `Decision` (with the constants), `AssetContext`, `CompensatingControl` | M1a |
| `assess` (19) | Those in `asset.go`, `control.go` and `report.go` | M2 |
| `gate` (11) | Those in `acceptance.go`, `audit.go` and `epss.go`, and 5 in `release.go` (`Vulnerability`, `VulnerabilityEnvelope`, `RiskBreakdown`, `ReleaseDecision`, `GateReport`) | M4 |
| `regulatory` (4) | Those in `art14.go` | M3 |

`Decision` has three module consumers: the gate (`releasegate`, and the `accept/cli` adapter), integrity (`statestore`, and the `cmd/state` adapter) and assess (`pkg/report`: `html.go`, `markdown.go` and `reader.go` use the type and its constants). The first measurement did not count the constants and saw only two. `AssetContext` and `CompensatingControl` have only the gate as a consumer, but they rise anyway: they are part of `Config` (`contracts/config`), which is shared, and `contracts` cannot import the gate. They rise by dependency, not by the two-consumer rule. `AuditEntry` appears in several places, but has consumers only in the gate and in adapters, so it belongs to the gate. `report.ReadReport` (`pkg/report/reader.go`, signature `ReadReport(path string, maxAgeHours int) ([]model.Vulnerability, string, error)`) returns a gate type: it is likely that the reader lives in `pkg/report` by mistake (to confirm in the M2 and M4 specs).

During migration, `pkg/model` keeps the 3 moved types as aliases (`type Decision = contracts.Decision`, plus the constants as `const DecisionAllow = contracts.DecisionAllow` and so on), so the 68 production files and 42 test files that import it continue to compile without edits. The aliases leave when the last owner migrates.

### 5.2 `pkg/contracts`

- **`contracts` (root):** `Decision` and the constants `DecisionAllow`, `DecisionBlock` and `DecisionWarn` (values `allow`, `block` and `warn`), `AssetContext` and `CompensatingControl`.
- **`contracts/exitcodes`:** `git mv` from `pkg/exitcodes`, with the contract test (which reads the source of the package itself). The constants are unchanged: 0, 1, 3, 4, 5, 6, 10, 11, 12 and 13. Add `FromError` (section 6).
- **`contracts/config`:** the types (`Config`, its sections and `Profile`), `Defaults()` (extracted from `Load`), `MigrateConfig`, `CurrentConfigSchemaVersion`, `DefaultForcedUpgradeTripwireFailures` and `Tripwire()`. No I/O and no environment variables. It imports the root `contracts` package for `AssetContext` and `CompensatingControl`.
- **`contracts/diag`:** `Diagnostic` (section 5.5).
- **`contracts/schema`:** output-contract versions and the v2 encoder (section 5.6).

### 5.3 `pkg/kit`

- **`kit/safeio`:** the current `pkg/cli`, renamed. It contains safe path I/O (`ValidateInputPath`, `ValidateOutputPath`, `SafePath`, `SafeOutputPath`, `SafeReadFile`, `SafeOpenFile`, `SafeWriteFile`, `ReadFile`) and the errors `ErrPathTraversal`, `ErrAbsolutePath` and `ErrInvalidPath`. The name `cli` was misleading. The tests and the fuzz targets move with it.
- **`kit/atomicwrite`:** `Write` and `WriteWithContext`. Consumers: `accept/store` (gate), `statestore` (integrity) and `safeio`.
- **`kit/configio`:** `Load` (read with `safeio`, strict decoding with `KnownFields(true)`, `MigrateConfig` and defaults when the file does not exist) and `ApplyProfile`, with `getActor` (reads `WARDEX_ACTOR`, `GITHUB_ACTOR` and `USER`).
- **`kit/cborcanon`:** the canonical CBOR mode, today initialised three times in an identical way (`pkg/attest`, `pkg/trust` and `internal/cpl`), each with its own `panic` in `init`. There will be one initialisation, with the same fail-fast behaviour. The library is `github.com/fxamacker/cbor/v2`, with `cbor.CanonicalEncOptions()` and `Time = cbor.TimeRFC3339`.

### 5.4 Splitting `config`

`Config` is a single struct with sections owned by several modules (`ReleaseGate`, `AcceptanceConfig`, `Art14Config`, `StateStoreConfig` and `ProvenanceConfig`, among others), used by every area. It stays a shared type (D2), and what performs I/O moves to `kit/configio`.

| Today (`config/`) | After |
| --- | --- |
| Types, `Tripwire()`, constants | `contracts/config` |
| `MigrateConfig`, `migrateV1ToV2` | `contracts/config` (pure) |
| Default values (a literal inside `Load`) | `contracts/config.Defaults()` |
| `Load`, 17 calls | `kit/configio.Load` |
| `ApplyProfile`, 2 calls, and `getActor` | `kit/configio` |

The only defaults today are `ReleaseGate.Mode = "any"` and `RiskAppetite = 0`, returned when the file does not exist. `Defaults()` must reproduce them without I/O. There is no validation today beyond strict decoding; M1 adds none (D5).

### 5.5 `Diagnostic`

```go
type Severity string // "info" or "warn"

type Diagnostic struct {
    Severity Severity
    Code     string            // <module>.<theme>.<cause>
    Message  string            // current text, so stderr stays the same
    Context  map[string]string // structured data for JSON v2
}
```

Warnings now travel in the result instead of being written by `ui.Warnf`. M1 adds the type and the renderer `ui.RenderDiagnostics`, which writes each diagnostic through the same logger and with the same text and level as today. The conversion of the sites happens in the owning modules. Current inventory (12 sites, 9 `warn` and 3 `info`):

| Site | Severity | Proposed code | Converted in |
| --- | --- | --- | --- |
| `snapshot/delta.go:26` | warn | `assess.snapshot.control_not_in_previous` | M2 |
| `analyzer/gap.go:34` | warn | `assess.mapping.unknown_control` | M2 |
| `art14/art14gen.go:235` | warn | `regulatory.art14.malformed_artefact_skipped` | M3 |
| `gate/pipeline.go:125` | info | `gate.enisa.stub_backend` | M4 |
| `sboms/cyclonedx.go:70` | info | `gate.sbom.vex_state_ignored` | M4 |
| `sboms/cyclonedx.go:130` | warn | `gate.sbom.empty_id_skipped` | M4 |
| `sboms/cyclonedx.go:133` | warn | `gate.sbom.no_cvss_skipped` | M4 |
| `sboms/openvex.go:75` | warn | `gate.sbom.unrecognized_state_skipped` | M4 |
| `epss/client.go:124` | warn | `gate.epss.malformed_skipped` | M4 |
| `epss/client.go:127` | warn | `gate.epss.out_of_range_skipped` | M4 |
| `trust/store.go:280` | warn | `integrity.trust.admin_key_decode_failed` | M5 |
| `statestore/store.go:236` | info | `integrity.statestore.history_cleaned` | M5 |

Until each module converts its sites, `diagnostics` in JSON v2 does not carry those warnings, which remain on stderr. The line numbers are from `a75500b`; re-check them after `/v3`.

### 5.6 Output contract: `schema` and JSON v2

- **v1** does not change and does not gain `schema_version`: that would be a visible change for its consumers.
- **v2** is opt-in (`--json-version v2`) and adds `schema_version: 2` and `diagnostics` at the top. Struct keys become snake_case (`GapReasons` gives `gap_reasons`; acronyms such as `CVSSScore` give `cvss_score`), existing `json` tags stay and map keys are not touched.
- `contracts/schema` exposes `Version` (`V1` and `V2`), `Parse` and `MarshalV2`. `assess` is the only v2 emitter in M1.
- `pkg/report/json.go` is the current v1 writer used by `assess`; v2 plugs into that path without changing the v1 output.
- `GapReport` already carries `json` tags with `omitempty` on `layer_delta` and `asset_compliance`; untagged fields such as `Summary` and `GateSummary` become `summary` and `gate_summary`. `CatalogControl` has only `yaml` tags, so its v2 keys come from the encoder.
- **Verification:** a conformance test ensures, for each v2 golden, that the key set is the v1 key set converted to snake_case (with an explicit list of data keys left out) and that every key matches `^[a-z][a-z0-9_]*$`.
- The values of the enumerations (`Covered`, `Partial`, `Gap`) stay verbatim in v2 (my proposal; ADR-003 fixes it). Converting the values is a second decision.

## 6. Error model

- **Exit codes.** The numeric contract stays: 0, 1, 3, 4, 5, 6, 10, 11, 12 and 13. 2 is reserved (POSIX) and, by the contract test, never produced.
- **`FromError(err) int`.** Uses `errors.Is` over sentinels defined in `exitcodes`: `ErrIntegrity` (3), `ErrStoreInconsistent` (4), `ErrGateBlocked` (10), `ErrComplianceFail` (11), `ErrActivelyExploited` (12) and `ErrDuplicateRelease` (13). Any other error gives 1 and `nil` gives 0. Codes 5 and 6 are not errors (operational warnings) and continue to be returned by the commands that compute them. Each module adopts the sentinels as it migrates, and `main` starts using `FromError`.
- **Recoverable warnings** are `Diagnostic`; errors remain `error`.
- **Known inconsistency.** `cmd/audit` ends with the literal `2` in 4 sites (`verify_link.go` and `verify_chain.go`), and `EXIT_CODES.md` documents that 2 for CPL, but the `exitcodes` test declares 2 reserved and never produced. M1 changes nothing (D5): it stays as `known_defect` in the G8 golden and is decided in the M5 spec. Options: name 2 and document the exception; change to 1 (breaks users of the documented code); keep.
- The contract test reads `exitcodes.go` and duplicates the documented table in Go; it does not parse `EXIT_CODES.md` or inspect the commands. The 2 discrepancy is therefore not caught today.

## 7. Standalone use

```go
cfg, err := configio.Load("wardex-config.yaml") // kit/configio
data, err := safeio.SafeReadFile(path)          // kit/safeio
out, err := schema.MarshalV2(result, diags)     // contracts/schema
os.Exit(exitcodes.FromError(err))               // contracts/exitcodes
```

The imports use `github.com/had-nu/wardex/v3/pkg/...`. `contracts` and `kit` compile and test on their own, without the rest of the repository: `go test ./pkg/contracts/... ./pkg/kit/...`.

## 8. Test plan

- **Golden G1 to G10 and the G1 matrix:** identical at the end of M1a (the `git diff` of `want/` is empty in that commit).
- **New v2 goldens** for `assess` (iso27001 and gdpr), with the trailer `Golden-Change: M1-P9`, plus the snake_case assertion.
- **v1 and v2 conformance** (section 5.6).
- **`cborcanon`:** fixed CBOR vectors generated before the change, compared byte-for-byte with the output of each of the three consumers.
- **`schema`:** a name table (`ID` gives `id`, `CVSSScore` gives `cvss_score`, `GapReasons` gives `gap_reasons`, `EPSSEnrichment` gives `epss_enrichment`) and a fuzz target with the property «idempotent and panic-free».
- **`ui.RenderDiagnostics`:** output byte-for-byte identical to `ui.Warnf` and `ui.Infof` for the same message.
- **`FromError`:** an error-to-code table, including wrapped errors.
- **Moved:** the `safeio` tests and fuzz, the `exitcodes` contract test and the `config` tests stay green. Five tracked `config` test files exist at the baseline; any test added before the split moves with them.
- **Sensitivity (≥ 4 of 5):** (m1) change an exit code constant; (m2) alter the authorisation logic of `ApplyProfile`; (m3) change the default `Mode` in `Defaults()`; (m4) change a canonical CBOR option; (m5) break the acronym conversion in snake_case.

## 9. Migration plan

| Step | Work | Acceptance criterion |
| --- | --- | --- |
| M1-P1 | Create `pkg/contracts` and `pkg/kit` in the manifest, without code | Boundary guard green |
| M1-P2 | `pkg/exitcodes` → `pkg/contracts/exitcodes` (9 production files and 8 test files import it) | Golden identical; contract test green |
| M1-P3 | `pkg/atomicwrite` → `kit/atomicwrite`; `pkg/cli` → `kit/safeio` (54 production files and 2 test files, 78 references), with a Go-aware tool | Build, `vet`, tests and fuzz green; golden identical |
| M1-P4 | `Decision`, `AssetContext` and `CompensatingControl` → `contracts`, with aliases in `model` | Golden identical |
| M1-P5 | `config` → `contracts/config` + `kit/configio` (17 `Load`, 2 `ApplyProfile`, 16 + 4 importers); extract `Defaults()` | Golden G3 and G7 identical; the five tracked `config` test files green |
| M1-P6 | `kit/cborcanon` and the replacement in the three sites | CBOR vectors equal; G7 to G9 identical |
| M1-P7 | End of M1a: update the boundary baseline | Entries for the moved packages removed; `config/` out of R7 |
| M1-P8 | `contracts/diag` + `ui.RenderDiagnostics` | Equivalence test green |
| M1-P9 | `contracts/schema` + `--json-version` in `assess` + v2 golden | v1 and v2 conformance green; v1 untouched |
| M1-P10 | `exitcodes.FromError` and the sentinels; `main` uses them | Exit codes identical in G3 and G8 |
| M1-P11 | Close: definition of done, review of ADR-003 and ADR-004 with what the implementation showed, tag `baseline/modular-1` | Section 10 |

Dependencies: P3 before P5 (the `configio` uses the `safeio`); P4 before P5 (the `config` uses two of the types); P8 before P9 (v2 carries `diagnostics`); P2 to P6 are mechanical, with an identical golden. Renames use a Go-aware tool, not `sed`.

## 10. Definition of done

- Golden G1 to G10 and the G1 matrix identical in the commit that ends M1a; v1 untouched at the end of the module.
- New v2 goldens for `assess` (iso27001 and gdpr) green, and v1 and v2 conformance green.
- Boundary guard: `contracts` and `kit` satisfy R1 and R2; the baseline no longer has entries for `pkg/exitcodes`, `pkg/cli`, `pkg/atomicwrite` or `config/`.
- `pkg/exitcodes`, `pkg/cli`, `pkg/atomicwrite` and `config/` no longer exist, with no stubs; `pkg/model` keeps only the 3 documented aliases.
- Coverage per package: moved code ≥ 60 %, new code (`diag`, `schema`, `cborcanon`, `FromError`) ≥ 80 %; floors updated.
- No `#nosec` without justification and no new `_ =` in the `contracts` and `kit` packages; `funlen` and `forbidigo` have no entries there.
- CBOR vectors identical before and after; sensitivity ≥ 4 of 5.
- ADR-003 and ADR-004 reviewed with what the implementation showed; this spec passes `check-specs`.
- Tag `baseline/modular-1` created and the branch merged into `main` (D10).

## 11. Risks

- **Renaming `pkg/cli` to `safeio` in 54 files.** It collides with the `accept/cli` and `enrich/cli` packages, also named `cli`. Mitigation: a Go-aware tool and compilation verified at each step.
- **Importing `config` as `config`.** It collides with local variables of the same name. Mitigation: an import alias where needed.
- **The reflection encoder.** It fails with types that implement `MarshalJSON`, with embedded structs or with `omitempty`. Mitigation: v2 only in `assess`, a conformance test and extension module by module. No type in `pkg` or `cmd` implements `MarshalJSON` today; the risk is future types.
- **The order of stderr changes** when the owning modules convert the sites (the warnings come out after the call). Mitigation: a golden with warnings per module and the renderer called at the same logical point.
- **Aliases in `pkg/model`** hide dependencies. Mitigation: baseline entries and removal in the last owner.
- **`contracts` is the first stable public API.** Mitigation: see «Not verified» about the stability level.
- **Moving CBOR to `kit`** moves the site of the `panic` in `init`. Mitigation: keep the fail-fast behaviour and the vector test.
- **Starting M1 before the prerequisites.** The module depends on `/v3`, rc.1 and M0. Mitigation: section 4 is a gate; the measurements are repeated after `/v3`.

## 12. Not verified

- **The `exitcodes` contract test:** confirmed that it parses `exitcodes.go`; it does not parse `EXIT_CODES.md`, and `TestDocumentedExitCodesAreImplemented` duplicates the documented table in Go. The 2 discrepancy in section 6 is therefore not caught by the test today.
- **`CatalogControl` and `GapReport`:** confirmed in `pkg/model/control.go` and `pkg/model/report.go`. `GapReport` already has `json` tags with `omitempty` on `layer_delta` and `asset_compliance`; no type in `pkg`, `cmd`, `internal` or `config` implements `MarshalJSON`.
- **`report.ReadReport`:** confirmed in `pkg/report/reader.go`, with the signature `ReadReport(path string, maxAgeHours int) ([]model.Vulnerability, string, error)`; it returns a gate type and unmarshals `model.GapReport`. Whether it belongs to the gate and dispenses with `kit/reportio` (D2) is decided in the M2 and M4 specs.
- **Uses affected by the `pkg/cli` rename:** 54 production files and 2 test files import it; there are 78 production call sites (`SafeReadFile` 27, `SafePath` 15, `ReadFile` 14, `SafeWriteFile` 12, `ValidateInputPath` 4, `SafeOutputPath` 4, `SafeOpenFile` 2), plus the test call sites. Counted at `a75500b`; recount after `/v3`.
- **Whether the order of stderr holds** when the owning modules convert the sites (it applies only after M1).
- **The stability-level convention** for public packages (for example `Stability:` in the package doc): D2 does not define it and ADR-002 may cover it.
- **`pkg/duration` and `pkg/utils`:** confirmed one consumer each at the baseline (`pkg/accept/cli/cli_handlers.go` and `pkg/orchestrator/gate.go`); whether they stay in the gate or the facade is confirmed in the M4 and M7 specs.
- **The name and exact version of the CBOR library:** confirmed `github.com/fxamacker/cbor/v2` v2.9.0 in `go.mod`; all three initialisations use `cbor.CanonicalEncOptions()` with `Time = cbor.TimeRFC3339`.
- **The working tree:** `config/config.go` and `internal/policy/loader.go` carry B1 and C1 (`M0#D8`) plus their tests. They must be committed in rc.1 before M1-P5; the spec assumes they do not collide with the `config` split.
- **The measurements** come from `main` @ `a75500b`; after `/v3` and rc.1 they must be repeated (the counts and the line numbers of the 12 sites may change). Any new `config` tests travel with the split.
