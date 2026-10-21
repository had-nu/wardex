# ADR-002 — Layout and encapsulation

- Status: Accepted
- Date: 2026-10-21
- Deciders: Wardex architecture
- Related: `M0#D2`, `M0#D5`, `M0#R1`, `M0#R2`, ADR-001

## Context

The current repository has one Go module and packages such as `pkg/analyzer`,
`pkg/gate` and `pkg/accept` that call each other directly. The package path does
not say which part is a public API and which part is an implementation detail.
Splitting into several Go modules now would multiply versioning and release
work before the internal boundaries are stable. A single module also lets the
golden harness build one binary and compare one set of cases.

## Decision

- One `go.mod` for the whole repository.
- Each module lives in `pkg/<module>/`; its public API is at that path and its
  implementation is under `pkg/<module>/internal/`.
- `contracts` contains pure types and has no I/O. It imports no repository
  package outside `pkg/contracts/...`.
- `kit` contains primitives and imports only the standard library, approved
  third-party libraries, `contracts`, and other `pkg/kit/...` packages.
- The two-consumer rule applies: a type or function rises to `contracts` only
  when at least two modules consume it. The facade and the adapters do not
  count, because they consume a module's public API.
- `config` splits into `pkg/contracts/config` (types, defaults, validation and
  migration) and `pkg/kit/configio` (`Load` and `ApplyProfile`).
- `doc/architecture/modules.yaml` records the allowed imports. The boundary
  guard enforces them; the Go compiler alone cannot, because the repository is
  still one Go module.

## Consequences

- `internal/` gives the compiler a second, local enforcement of encapsulation.
- A single Go module keeps `go test ./...`, the golden harness and the release
  build simple during the migration.
- Cross-module imports remain visible in one dependency graph and are checked
  by `tools/check-boundaries`.
- If a module later needs an independent release cadence, extracting it is a
  deliberate follow-up. The layout does not make that extraction free, but it
  does make the boundary explicit.
- The two-consumer rule keeps `contracts` small. A shared type that only one
  module uses stays with its owner.

## Alternatives rejected

- **Multi-module `go.work` during modularisation.** Rejected because it adds
  per-module versioning, tagging and release plumbing before the boundaries
  are stable, while the repository is still delivered as one binary.
- **Flat `pkg/*` packages without `internal/`.** Rejected because every package
  would remain importable from every adapter, and the boundary guard would be
  the only protection.
- **A separate repository per module.** Rejected for the same reason as
  `go.work`, with more coordination cost.
- **A single `contracts` package containing I/O helpers.** Rejected in ADR-005:
  it would make pure types depend on the filesystem and the environment.
