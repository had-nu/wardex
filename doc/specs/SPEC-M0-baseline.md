# SPEC-M0 — Baseline: repository safety net and hygiene

Wardex · draft 0.3 · 20 October 2026 · base: `main` @ `a75500b` (24 commits after v2.6.1)

## 1. Purpose

Module 0 does not deliver functionality. It delivers the means to verify that modularisation (modules 1 to 5) does not change Wardex's behaviour and that module boundaries hold. Without it, "equally consolidated" is an intention, not a verifiable property.

It produces six things:

1. golden characterisation tests for the integrated flows;
2. a boundary guard with a baseline;
3. quality floors that only rise;
4. repository hygiene that depends on no module;
5. the ADRs and templates that later modules will use;
6. spec normalisation: the same structure and nomenclature in every spec, checked by tooling.

## 2. Scope

**In:** verification tooling, baselines, ADRs, templates, spec normalisation, moving files that are not production code and have automated verification, and prerequisite P0 (section 4). The text owned by M0 is UK English. The repository-wide language migration is a separate workstream.

**Out:** moving production code between packages, changing behaviour (except M0-P0.2), the AIPD functionality, and everything that belongs to a module (simulator, `frameworks/`, `templates/`, `spec/cddl`, `config/`). Those items are listed in 5.4-B and travel with the owning module. The UK English documentation migration is tracked separately; it runs in parallel and does not block M0 beyond the golden sequencing in M0-P0.3.

## 3. Inherited decisions

D1 to D13 are mandatory and closed. They prevail over any earlier analysis or plan that contradicts them, including the 19 October review with notes L1 to L19. Points from that review that do not collide with them (for example the shape of `Diagnostic`, the composition of `convert` with `attest`, and the version seal) are starting material for the owning module specs, not decisions.

| # | Decision (mandatory) |
| --- | --- |
| D1 | Order: 0 → contracts → assess → regulatory → gate → integrity, with the mechanical `/v3` path PR (D7) between M0 and M1. `regulatory` precedes `gate` because `accept/cli` imports `art14`. `adapters` and `facade` grow with each module; they are not final phases. |
| D2 | One `go.mod`. Each module in `pkg/<module>/` (public API) with the implementation in `pkg/<module>/internal/`. `contracts` are pure types, with no I/O, and import no repository packages; `kit` contains primitives and imports only `contracts`. Two-consumer rule: only what at least two modules use moves up to `contracts`. `config` splits into `pkg/contracts/config` (types, defaults, profiles, migration, validation) and `pkg/kit/configio` (`Load`, `ApplyProfile`). Planned primitives: `kit/reportio` and `kit/canonicalhash`, confirmed in the M2 and M5 specs. |
| D3 | JSON: `schema_version: 2` in snake_case, opt-in by flag (proposed name `--json-version`, values `v1` and `v2`, fixed in ADR-003). v1 (PascalCase) is the default until v3.0.0. M0 freezes v1; M1 adds v2 and the golden tests freeze both; the default flips in M7, with `Golden-Change`. |
| D4 | Errors: one error type → exit code in `contracts`; `Diagnostic` in the result instead of `ui.Warnf`. The exact shape of `Diagnostic` and its presence in JSON v2 are closed in the M1 spec. |
| D5 | Restructuring and adding functionality do not mix. A golden test changes only with an approved `Golden-Change:` trailer. |
| D6 | Spec structure and nomenclature are the same for all modules (section 5.6). Definition of done is the same for all (section 10). |
| D7 | Go module path: from `github.com/had-nu/wardex/v2` to `/v3`, in a dedicated mechanical PR between M0 and M1 (ADR-006), with checks for README and `examples/sdk`. Without it there is no installable v3.0.0 tag. Do not mix it with M1. |
| D8 | `v2.7.0-rc.1` is a pre-release and the baseline, with C1, B1, M0-P0.2, the M0-P0.3 UK English migration of user-facing output, and the CHANGELOG. C1 and B1 are in the working tree of `release/2.7.0` and must be committed before the cut; the branch is at `a75500bd` (= `main`). The baseline is cut after M0-P0.2 and M0-P0.3. |
| D9 | AIPD and the unification of `internal/policy` with `pkg/ingestion` come after modularisation. M2 only relocates `internal/policy` to `pkg/assess/internal/policy` and exposes the service in the facade. AIPD is a new, additive package and can run in parallel after M2. |
| D10 | Each module merges into `main` when its acceptance criterion closes. `main` is always installable and v3.0.0 is released only at the end of M7. There are no stacked branches. |
| D11 | Reference plan (schedule): M0 and M1 are guaranteed; M2 enters only if `G1-min` stays at three cases per flow and the cost of `G1-matrix` fits the M2 estimate. The two-week schedule has not been validated. Estimates from the 19 October review, not validated: M0 5 to 7 days, M1 3 to 4, M2 4 to 5. |
| D12 | Precedence: this spec and decisions D1 to D13 prevail over any earlier analysis that contradicts them. |
| D13 | UK English is the project language. All prose, comments, user-facing messages and documentation are UK English. Go keywords and existing public identifiers and schema values are not translated or renamed for spelling in M0; new identifiers use UK English. Vocabulary: `module` is the architectural unit, `component` is a deliverable within a module, `package` is a Go package, `Go module` is the `go.mod` unit. Portuguese terms (`pacote`, `módulo`, `componente`, `arquivo`, `linha de base`) are forbidden. Historical specs are archived as `legacy-pt` with an English abstract. The documentation migration runs in parallel with M0 and M1. |

## 4. Prerequisites

P0 is the prerequisite: an installable baseline. Context: the v2.6.1 binary does not have the `gdpr` and `cra` catalogues; `main` does. The `CHANGELOG [Unreleased]` is empty despite 24 commits, one of which removes SOC 2 (an incompatible change). M0-P0.1 is confirmed by the execution reported in the 19 October review; it was not reproduced in this analysis. A control implemented at maturity 4, with evidence and `domains: [governance]`, assessed against the GDPR, leaves GDPR.35 in Partial and never reaches Covered. The cause is in `pkg/correlator/matcher.go`: `matchDomains` compares against `annexA.Domains`; only `annex_a.yaml` declares `domains:` (93 occurrences), the other six catalogues have zero, and `catalog.Load` does not derive `Domains` from `Domain`.

- **M0-P0.1** Confirmed: the defect was confirmed by the execution reported in the review. Done.
- **M0-P0.2** Fix in a dedicated PR (derive `Domains` from `domain` in the loader, or an explicit `maps_to` mapping). The PR includes a GDPR behaviour test and the before/after for the other frameworks without `domains` (NIS2, DORA, EU AI Act, CRA), because their results also change.
- **M0-P0.3** Migrate user-facing output to UK English before the baseline: CLI help, errors, warnings, dashboards, Markdown and HTML reports, templates, test messages and internal comments. No behaviour change. Audit JSON v1 keys and enum values first; keys must not change. This is the language part of the baseline.
- **M0-P0.4** Write the `CHANGELOG`, mark the SOC 2 removal as incompatible, and cut `v2.7.0-rc.1` as a pre-release (D8), with C1, B1, M0-P0.2 and M0-P0.3. That binary is the golden baseline and gives the DigiToys work a binary with GDPR.
- **M0-P0.5** Remove the Docker plumbing from the repository until v3: `Dockerfile`, `.dockerignore`, `docker-compose.yml`, the `Docker` workflow and the repository's Docker Action (`action.yml`); `docker_signs` dropped from GoReleaser. Container images are no longer published; the Helm image default freezes. Existing tags keep working, and the container distribution returns with v3.

M0-P0.2 is mandatory, and the baseline is cut only after it. C1 and B1 must be committed before M0-P0.4. The UK English documentation migration runs in parallel and does not block the baseline.

## 5. Components

| Field | Value |
| --- | --- |
| Inputs | The repository at `main` @ `a75500b`; the 19 October review; the existing tools in `tools/`; the CI workflow. |
| Outputs | Golden harness, boundary guard, ratchet baselines, hygiene changes, ADRs, spec template, glossary and `check-specs`. |
| Public API | None (tooling and tests). |
| Allowed dependencies | Standard library and the existing `gopkg.in/yaml.v3`. |
| Absorbed packages | None. |
| Absorbed commands | None. |
| Branch | `mod/0-baseline`. |
| Estimate | 5 to 7 days (not validated). |

### 5.1 Golden harness

**Method.** Black box. `TestMain` compiles the binary once with the release flags (`-trimpath`). Each case copies `in/` to a temporary directory, runs the binary and captures stdout, stderr, exit code and the declared files. It uses only the command line, so it survives package moves. It runs with `go test -tags golden ./test/golden/...`, outside the normal `go test ./...`.

```
test/golden/
  harness_test.go     # runner (build tag golden)
  normalise.go        # normalisation rules
  cases/<flow>/<case>/
    case.yaml
    in/               # inputs (includes test keys, not secrets)
    want/stdout.txt  want/stderr.txt  want/exit  want/files/
```

```yaml
# case.yaml
id: assess-iso27001-both-layers
flow: G1
args: [assess, documented.yaml, implemented.yaml, --framework, iso27001, --output, json]
outputs: []                      # produced files to compare
normalise: [timestamps, tmpdir, version]
known_defect: ''                 # issue id or short description, if the current result is a known defect
env: {}                          # optional: deterministic fixture secrets
modes: {}                        # optional: file modes to apply after copying in/, e.g. {admin: "0600"}
```

`env` and `modes` are harness extensions, not product inputs. `env` exists so a
case that needs `WARDEX_ACCEPT_SECRET` uses a fixture secret instead of the
developer's shell. `modes` exists because git records only the executable bit:
a private-key fixture that the product refuses to read at 0644 would pass
locally and fail on a fresh clone.

**Normalisation.** RFC 3339 timestamps, the space-separated form reports use in
HTML (`YYYY-MM-DD HH:MM:SS`), and the standard logger's prefix
(`YYYY/MM/DD HH:MM:SS`) → `<TS>`; temporary directory path → `<TMP>`; version →
`<VERSION>`; LF line endings; JSON re-encoded with fixed indentation before
comparison. Any other instability (map order, randomness, network) is a defect
in the case and is not solved by widening the normalisation.

**Determinism.** Each case runs twice; if the normalised results differ, the case is rejected.

**Isolation.** No network (EPSS from a local file, via `epssPath`). No key generation: the test Ed25519 keys are in the inputs, marked as non-secret; `keygen` is tested only for format and permissions. `provenance` uses only the noop and embedded drivers (gRPC is behind a build tag and stays out).

**Update policy.** `make golden-update` rewrites `want/`. CI fails if `test/golden/**/want/**` changes in a PR without the `Golden-Change: <ADR or issue>` trailer on a commit. A case with `known_defect` changes only in the PR that fixes the defect, with the trailer.

**Mandatory flows** (minimum of three cases per flow: happy path, expected failure with exit code, invalid input):

| Flow | Commands | Frozen content |
| --- | --- | --- |
| G1 | `assess` | 7 frameworks (iso27001, nis2, dora, eu_ai_act, nist_csf, gdpr, cra) × {documented only, implemented only, both, with assets}; JSON in all, Markdown/CSV/HTML for iso27001 and gdpr |
| G2 | `assess` + snapshot | save and compare → delta |
| G3 | `evaluate` | vulnerabilities → decision and exit code, with acceptances, local EPSS and active exploitation |
| G4 | `convert` | Grype and KEV → YAML; read CycloneDX, SPDX and OpenVEX |
| G5 | `aggregate` | several results → one decision |
| G6 | `art14` | complete artefact lifecycle |
| G7 | `trust`, `auth`, `config seal` | with fixture keys |
| G8 | `chain`, `state`, `gate`, `audit`, `hmac`, `contract` | including the version seal (exit 13) |
| G9 | `provenance` | noop and embedded drivers |
| G10 | `policy` | files from `frameworks/` |

**G1 matrix.** The matrix is defined as data in `cases/G1/matrix.yaml`, with axes `framework`, `layers`, `assets` and `format`. The harness expands it into IDs (`G1-<framework>-<layers>-<format>`, with an `-assets` suffix when the assets axis is set) and stores each `want/` in `cases/G1/want/<id>/`. All matrix entries share `cases/G1/in/`. `G1-min` is at least three cases per flow for P2 and P3; `G1-matrix` is the complete matrix and the M0 exit criterion. D11's "three cases per flow" condition refers to `G1-min`; the M2 decision uses the cost of `G1-matrix`. Define `matrix.yaml` as an explicit list of combinations, not a Cartesian product: 7 frameworks × 3 layer modes × 2 asset modes × 4 formats would be about 168 cases and would not fit the M0 estimate. HTML is compared in full: its timestamp is normalised and the document carries no other volatile content.

**Frozen defects.** P3 found two current behaviours that the goldens record
rather than fix, because M0 changes no product code:

- `policy add` rejects a relative `--file` with "path traversal detected",
  because `ValidateInputPath` compares a relative joined path with an absolute
  base. The `policy-add` case captures the rejection.
- `accept request` computes the config hash and then omits it from the stored
  acceptance, so `evaluate` rejects every acceptance it created with "config
  changed since acceptance". The `evaluate-acceptance-rejected` case captures
  the rejection.

Both cases carry `known_defect` with the description. A change to either
behaviour requires a `Golden-Change` trailer and the fix's PR.

`simulate` keeps only a start and end test, with no content golden. The flags of each command are discovered with `--help` in the implementation.

### 5.2 Boundary guard

Tool `tools/check-boundaries`, in the same convention as the existing tools (`go run`, no new external dependencies), runs in the CI Test job.

```yaml
# doc/architecture/modules.yaml
version: 1
modules:
  contracts:  { packages: [pkg/contracts],  may_import: [] }
  kit:        { packages: [pkg/kit],        may_import: [contracts] }
  assess:     { packages: [pkg/assess],     may_import: [contracts, kit] }
  regulatory: { packages: [pkg/regulatory], may_import: [contracts, kit] }
  gate:       { packages: [pkg/gate],       may_import: [contracts, kit] }
  integrity:  { packages: [pkg/integrity],  may_import: [contracts, kit] }
  facade:     { packages: [pkg/sdk],        may_import: [assess, regulatory, gate, integrity, contracts, kit] }
  adapters:   { packages: [cmd, pkg/ui, .], may_import: [facade, contracts, kit] }
  tests:      { packages: [test, examples], may_import: [facade, contracts, kit] }
  tools:      { packages: [tools],          may_import: [] }
legacy:   # generated by `check-boundaries -init` from the current graph
  - { package: pkg/analyzer, target: assess, allow: [pkg/ui] }
  - { package: pkg/accept/cli, target: gate, allow: [pkg/art14, pkg/ui] }
```

**Rules**

- R1 `contracts` imports no repository packages; `kit` imports only `contracts`.
- R2 A module imports only `contracts`, `kit` and its own packages.
- R3 Only the `facade` imports more than one module.
- R4 Only the `adapters` import `pkg/ui`.
- R5 The `adapters` use only the public API of the modules.
- R6 An unclassified package (neither in `modules` nor in `legacy`) is an error.
- R7 Production code outside `pkg/` (today `config/`, `internal/cpl`, `internal/policy`, `internal/notification`) must have a destination in the manifest.
- R8 `tools/` is a leaf: it imports no repository packages.

**Classification and execution.** `tools/` is a leaf; `test/` and `examples/` are classified as `tests` and consume only the facade, `contracts` and `kit`. The checker also runs with `-tags grpc`, to catch `provenance/grpc.go`, and ignores imports in `_test.go` files. Current exception: `test/security/crypto_audit_test.go` imports `pkg/accept`; `-init` will baseline it, or the test moves to the gate module.

**Baseline.** The `legacy` section lists the current violations (for example `analyzer → ui`, `accept/cli → art14`, the 22 imports of `orchestrator`). The tool fails when a new violation appears and also when a baseline violation disappears without being removed from the file, so the baseline does not go stale. After each module migrates, `internal/` enforces encapsulation through the compiler and the manifest continues to enforce the contracts between modules.

### 5.3 Quality floors

Tool `tools/check-ratchet`, baselines in `tools/baselines/`.

- **Coverage per package.** Reads the `-coverprofile` and compares it with `coverage.json`. Initial floor = current coverage rounded down. The floor only rises (`make ratchet-update` refuses decreases). The global 40% threshold stays. Packages without tests (`pkg/model`, `pkg/gate`, `pkg/accept/rules`, `pkg/utils`) enter with floor 0 and the `untested` marker.
- **Lint.** Remove the three `errcheck` exclusions by `_ =` pattern, which neutralise `check-blank: true`, and review the `research/` exclusion. `research/` is a local, git-ignored directory, not a nonexistent path; decide whether the exclusion should stay for local scratch files or be removed. Add `funlen` (proposal: 100 lines, 60 statements) and `forbidigo` (`os.Exit`, `fmt.Print*`) with a baseline. Today there are about 64 `_ =` in `pkg/` and 18 functions above 100 lines.
- **Lint baseline mechanism.** `issues.new-from-rev` pinned to the `baseline/modular-0` tag, or the v2.15 equivalent (syntax to confirm). Alternative: a baseline file generated by tooling.
- **`#nosec`.** `tools/check-nosec` fails on a `#nosec` without a rule code and a justification. Baseline: the 20 current occurrences without justification (of 40).
- **Rule per module.** Moved code ≥ 60% coverage; new code ≥ 80%. Each module removes its packages' entries from the baseline.

### 5.4 Repository hygiene

**A. Done in module 0**

- `doc/INDEX.md` includes the repository map: `doc/` documentation, `docs/` published site (GitHub Pages, not renamed because Pages serves from this directory), `spec/cddl` CDDL schemas, `test/` tests.
- `chain-seal-v2.4.0.json` and `chain-seal-v2.4.1.json` → `doc/releases/seals/`. Update the two references (`doc/releases/v2.4.0-notes.md` and `CHANGELOG.md`). Verification: `check-doclinks`, plus confirmation that no CI workflow reads them from the root.
- Review the lint exclusion for `research/`; the directory is local and ignored, so the original "nonexistent" justification is wrong.
- New `Makefile` targets (section 7).
- `lazygo.yml` is generated by lazy.go; `.gitignore` references `lazygo.yml.bak`. Confirm its purpose with the author. If it is personal configuration, stop versioning it.

**B. Travels with the owning module (do not touch now)**

| Item | Destination |
| --- | --- |
| `config/` (Go package outside `pkg/`) | contracts: splits into `contracts/config` and `kit/configio` (D2) |
| `pkg/catalog/*.yaml` and `frameworks/*.yml` | assess. Confirmed: `pkg/catalog` is the normative embedded catalogue (`catalog.Load`, `embed.FS`, fields `id`, `name`, `domain`, `keywords`, `base_score`, `practices`); `frameworks/` are operator assertions (`policy.LoadFramework`, fields `status`, `maturity`, `implementation_note`, `last_assessed`). Distinct layers, not duplicates. `frameworks/` has no operator skeletons for gdpr, cra or nist_csf; `annex_a` is a catalogue annex, not a framework. Renaming `frameworks/` to `policies/` is a hypothesis for the M2 spec. |
| `test/wardex-risk-simulator.jsx` and `test/embed.go` (embedded by `cmd/simulate`) | gate: the content moves to the gate package and is exposed by its public API, through the facade, because the gate `internal/` is not accessible to the adapters. The root `test` package disappears and `test/` holds tests only. |
| `data/` (`calibration.json`, `dataset_2025-03-01.json`), `testdata/` at the root, `test/testdata/` | inventory who reads each one; Go convention: `testdata/` next to the package |
| `templates/*.tmpl`, `signatures/version1`, `spec/cddl` | integrity |
| `dashboard_view.go` and tests in the root `package main` | adapters, with the first migrated command |
| `INPUT_GUIDE.md`, `RELEASES.md` at the root | consider moving to `doc/` after checking references in code and README |

### 5.5 ADRs and templates

In `doc/architecture/adr/`, one page each (context, decision, consequences, alternatives rejected):

- ADR-001 order and modules (alternative rejected: order by runtime use);
- ADR-002 layout and encapsulation (alternative rejected: multi-module `go.work`);
- ADR-003 JSON v2 policy and the v1 deprecation window;
- ADR-004 errors and `Diagnostic`;
- ADR-005 definition of done, floors and golden policy (alternative rejected: a single `contracts` without `kit`);
- ADR-006 Go module path to `/v3` (alternatives rejected: raise inside M1, raise only in M7, do not raise);
- ADR-007 `ADR-007-uk-english.md`: UK English as the project language and vocabulary (alternatives rejected: Portuguese-first documentation; per-file language choice).

Spec template in `doc/specs/TEMPLATE_module.md`, generated from the canonical structure in section 5.6 and validated by `check-specs`.

### 5.6 Spec normalisation

All specs (M0 to M7 and the transversal specs) follow the same structure and nomenclature, and this is verified by tooling, not by review.

**Canonical structure.** Twelve sections, in the same order and with the same titles in every spec. A section with no applicable content says "N/A" and the reason on one line; it is never omitted.

| # | Fixed title | Content |
| --- | --- | --- |
| 1 | Purpose | what the module delivers and why |
| 2 | Scope | in and out |
| 3 | Inherited decisions | decision table: global decisions by reference, module decisions as `M<n>-D<k>` |
| 4 | Prerequisites | what must exist first (modules, PRs, baseline) |
| 5 | Components | opens with the module card; then one subsection per component (`5.1`, `5.2`) |
| 6 | Error model | error types, exit codes, diagnostics |
| 7 | Standalone use | how to use the module alone, by command or code example |
| 8 | Test plan | golden, unit, fuzz, boundary, sensitivity |
| 9 | Migration plan | steps `M<n>-P<k>` with acceptance criterion |
| 10 | Definition of done | verifiable list |
| 11 | Risks | risk and mitigation |
| 12 | Not verified | what was not confirmed and how to confirm it |

**Module card.** Table at the start of section 5, with the same eight rows in every spec: Inputs, Outputs, Public API, Allowed dependencies, Absorbed packages, Absorbed commands, Branch, Estimate. In M0: no public API (they are tools and tests), standard library plus the existing `gopkg.in/yaml.v3` (see section 12), no absorbed packages or commands, branch `mod/0-baseline`.

**Nomenclature.**

| Element | Format | Example |
| --- | --- | --- |
| Spec file | `doc/specs/SPEC-M<n>-<id>.md`; transversal `SPEC-X-<topic>.md` | `SPEC-M2-assess.md`, `SPEC-X-help.md` |
| `<id>` | module id in the manifest, lowercase; `baseline` for M0 | `contracts`, `gate` |
| Title | `SPEC-M<n> — <Name>` | `SPEC-M0 — Baseline: repository safety net and hygiene` |
| Byline | `Wardex · <state> <version> · <date> · base: <ref>`; states `draft`, `accepted`, `implemented`, `legacy`, `legacy-pt` | `Wardex · draft 0.3 · 20 October 2026 · base: main @ a75500b` |
| Decision | `D<n>` global; `M<n>-D<k>` module | `D7`, `M1-D2` |
| Rule, flow, component | `R<n>`, `G<n>`, `<section>.<n>` | `R4`, `G3`, `5.2` |
| Step | `M<n>-P<k>`; sub-step `M<n>-P<k>.<j>` | `M0-P5`, `M0-P0.3` |
| Cross-reference | `<spec>#<id>` | `M0#R4` |
| ADR | `doc/architecture/adr/ADR-<nnn>-<slug>.md` | `ADR-006-go-module-v3.md` |
| Branch and tag | `mod/<n>-<id>` and `baseline/modular-<n>` | `mod/1-contracts` |

**Glossary.** One term per concept, in `doc/specs/glossary.yaml` (the source the tool reads). The table below is definitional; the tool reads the YAML and exempts this table from the forbidden-term scan.

| Canonical term | Do not use |
| --- | --- |
| baseline | linha de base |
| golden test | characterisation test (first definition only) |
| floor (coverage) | ratchet, except in `check-ratchet` |
| boundary guard | boundary check |
| module (aggregates packages) | package or component when meaning module |
| component (deliverable within a module) | module |
| definition of done (module) | closure criteria; "acceptance criterion" is only for steps |
| file | arquivo |
| package (Go) | pacote |
| Go module | module when meaning `go.mod` |
| catalogue | catalog in prose (the code path `pkg/catalog` is unchanged) |

`package`, `func`, `type`, `map` and the other Go keywords are reserved terms: do not translate them and do not use them for product concepts.

**Tool.** `tools/check-specs`, in the same convention as the other tools (`go run`, no new external dependencies; it may use the existing `gopkg.in/yaml.v3`). It runs in CI with `check-doclinks`. It checks: file name and title; byline; the 12 sections, in order and with the exact titles; the module card with the eight rows; unique IDs per spec and cross-references that resolve; forbidden Portuguese terms outside code spans and outside the glossary table; the reserved-term list in the glossary; glossary definitions; and that the template itself complies. It uses the exit codes in section 6. `legacy-pt` specs are exempt from the content, name and byline rules, but they require a manifest entry and an English abstract.

**Scope and inventory.** Specs M0 to M7, transversal specs (for example AIPD and help/manual, when they exist) and ADRs (fixed format: context, decision, consequences, alternatives rejected). Existing specs in `doc/specs/` are inventoried in `doc/specs/specs.yaml` and classified as `legacy-pt` with an English abstract, or `active`. The 10 historical specs and the Portuguese working drafts of M0 and M1 are `legacy-pt`; M0 and M1 are active. Source of truth: the repository. The editable document is a drafting artefact only; after conversion it is archived or marked obsolete with a pointer to the repository spec.

**Conversion of this spec.** This English version is the first `check-specs` case (M0-P8): canonical title and byline, section 4 renamed "Prerequisites" with P0 inside, module card at the start of section 5, steps renamed `M0-P<k>`, glossary applied, and the file moved to `doc/specs/SPEC-M0-baseline.md`. The Portuguese working draft is kept as `legacy-pt` for reference only.

## 6. Error model

The tools share one error model. Common exit codes: `0` no violations; `1` new violation; `2` configuration, manifest or baseline error; `3` unclassified item or non-deterministic case. Messages follow `file:line RULE description`, with optional `-json`.

## 7. Standalone use

```
make golden            # go test -tags golden ./test/golden/...
make golden-update     # rewrites want/ (requires Golden-Change trailer)
make boundaries        # go run ./tools/check-boundaries
make coverage-table    # go test -coverprofile + per-package table
make ratchet           # coverage per package, nosec and lint against the baselines
make ratchet-update    # accepts increases only
make specs             # go run ./tools/check-specs
make language          # go run ./tools/check-language
make baseline-check    # everything above, same as the CI job
```

`make specs` exists now; the other targets are created by the step that owns
them. `make language` belongs to the parallel UK English workstream, not to
M0's critical path.

## 8. Test plan

The test plan covers the module itself, not the product flows. It includes:

- **Normaliser:** table of inputs (timestamps in several formats, paths, version) → expected output.
- **Boundary guard:** synthetic graphs, one violation per rule R1 to R8, and a baseline that goes stale.
- **Floors:** increase accepted, decrease rejected, new package without a floor.
- **Harness:** double run on every case.
- **Spec normalisation:** synthetic specs, one violation per `check-specs` rule (name, byline, missing or out-of-order section, incomplete card, duplicate ID, broken cross-reference, forbidden Portuguese term such as `pacote`, missing glossary definition); the template complies with the same rules.
- **Language checker:** a fixture with legitimate `package` uses passes; `pacote` fails; the M0 spec and the template pass; the baseline ratchets down.
- **Sensitivity (manual, before closing the module):** apply five mutants to `main`; the golden run must fail for at least four. (m1) the fixed maturity threshold in `EvaluateCoverage`; (m2) a gate exit code; (m3) remove `layer_delta` from the `assess` JSON; (m4) reverse the roadmap order; (m5) the confidence returned by `matchDomains`.

## 9. Migration plan

| Step | Work | Acceptance criterion |
| --- | --- | --- |
| M0-P0 | Section 4 (M0-P0.1 to M0-P0.5 done) | `v2.7.0-rc.1` published as a pre-release, with C1, B1, M0-P0.2, M0-P0.3 and CHANGELOG; Docker plumbing removed (M0-P0.5) |
| M0-P1 | Measure real coverage per package in CI | table per package published as an artefact |
| M0-P2 | Harness + normaliser + 3 G1 cases | double run stable; 3 cases green in CI |
| M0-P3 | Cases G1 to G10, with the G1 matrix generated from data | ≥ 3 cases per flow green on rc.1; complete matrix green before closing M0 |
| M0-P4 | Boundary guard with `-init`, including `tools`, `test` and `examples` in the manifest | green on `main` with and without `-tags grpc`; an injected new violation fails |
| M0-P5 | Coverage, lint and `#nosec` baselines; remove exclusions | CI green; an injected regression fails |
| M0-P6 | Hygiene A | `check-doclinks` green; nothing reads the moved files from the root |
| M0-P7 | 7 ADRs and spec template | 7 ADRs accepted; template created per section 5.6 |
| M0-P8 | Spec normalisation (5.6): glossary, `check-specs`, `doc/specs/` inventory, conversion of this spec | `check-specs` green in CI; all specs compliant or `legacy-pt`; the template validates itself |
| M0-P9 | Sensitivity and tag `baseline/modular-0` | ≥ 4 of 5 mutants detected; tag created |

Dependencies: P1 before P5; P2 before P3; P7 before P8; P4, P6 and P7 are independent of each other; P9 is last. The `/v3` PR (D7) comes after M0 and before M1. P8 estimate (mine, to validate): 1 to 2 days for spec normalisation, plus 1 to 2 days for the UK English conversion of this spec and the glossary.

## 10. Definition of done

- The 10 flows have ≥ 3 cases, stable in double run and green on rc.1, and the G1 matrix is complete.
- The boundary guard runs in CI (with and without `-tags grpc`), with a generated baseline, and an injected regression fails.
- Coverage, lint and `#nosec` baselines are in CI, and an injected regression fails.
- The exclusions that neutralised `errcheck` and the `research/` exclusion have been reviewed; `research/` is local and ignored, so the action is decided on that basis.
- Hygiene A is complete and `check-doclinks` passes.
- The 7 ADRs, the spec template and the glossary are in the repository.
- `check-specs` runs in CI; all specs are compliant or `legacy-pt`, and this spec is converted.
- All new and changed text owned by M0 is UK English; `check-language` passes for the M0 scope. The repository-wide documentation migration is a separate workstream and is not an M0 exit criterion.
- The help (`--help`) and manual (`README.md`/`docs/`) for new or changed commands are up to date; `check-doclinks` passes.
- Sensitivity is ≥ 4 of 5.
- No production file has changed since `v2.7.0-rc.1`, proven with `git diff --stat v2.7.0-rc.1..HEAD -- pkg cmd`.

## 11. Risks

- **Unstable golden** (time, order, network). Mitigation: strict normalisation, double run, no network, fixture keys.
- **Fragile golden in HTML.** Mitigation: compare after normalisation; if fragility persists, reduce to invariants (headings, counts).
- **Baseline that freezes defects.** Mitigation: `known_defect` and the `Golden-Change` trailer.
- **Stale boundary baseline.** Mitigation: the tool fails when a violation disappears without being removed from the file.
- **Moving files breaks links or CI.** Mitigation: `check-doclinks` and a reference search before moving.
- **Too many tools for one maintainer.** Mitigation: small tools in `tools/`, in the existing convention, with no new external dependencies.
- **Spec normalisation becomes bureaucracy.** Mitigation: `check-specs` validates structure, IDs and vocabulary, never content; `legacy-pt` specs are exempt.
- **`/v3` path breaks imports or README.** Mitigation: dedicated mechanical PR (D7), with golden and boundary guard as the safety net.
- **Toolchain.** CI uses Go 1.27.2; document it in `CONTRIBUTING.md`.
- **UK English migration touches output and docs.** Mitigation: M0-P0.3 before the baseline; documentation in parallel; `check-language` ratchets down; existing identifiers and schema values are not renamed for spelling in M0.

## 12. Not verified

The following points were not verified in this analysis. Resolve them during implementation.

- Flags and output formats of each command (`--help`).
- Real coverage per package (the full test suite passes, but per-package coverage was not recorded for this spec).
- The baseline syntax of golangci-lint v2.15.
- The purpose of `lazygo.yml`, `data/`, `signatures/version1`, and whether `wardex-config.yaml` at the root is used by CI.
- Whether the `chain-seal-*.json` files are read by any verification flow from the root.
- C1 and B1: committed on `release/2.7.0` before the rc.1 cut (`954bdb02`, `c843aeab`). The Article 13(8) soft check is wired into the gate in `af66a5ee`, conditional on a declared CRA product; a validator with no call site would have been a dead configuration path.
- `pkg/catalog` versus `frameworks/`: confirmed distinct layers (normative catalogue versus operator assertions).
- `doc/specs/`: 10 historical specs, the active M0 and M1 specs, and the Portuguese working drafts marked `legacy-pt`; source of truth is the repository. Historical specs are archived as `legacy-pt` with English abstracts.
- M6 and M7 are referenced in D3, D10, 5.5 and 5.6 but are not defined in the module map; define them or rename them as phases.
- G1 matrix size and D11: separate `G1-min` (three cases per flow) from `G1-matrix` (M0 exit); D11's M2 condition must be assessed against the cost of `G1-matrix`. If `matrix.yaml` is a Cartesian product, about 168 cases; define explicit combinations.
- Tools and YAML: `check-boundaries` and `check-specs` read YAML; use the existing `gopkg.in/yaml.v3`, with no new dependency. Clarify "no external dependencies" versus "standard library only".
- `test/security/crypto_audit_test.go` imports `pkg/accept`; the `tests` rule allows only facade, `contracts` and `kit`. P4 needs a legacy entry or the test moves to the gate module.
- The `research/` exclusion points to a local, git-ignored directory, not a nonexistent path; the 5.3 and 5.4-A action must be decided on that basis.
