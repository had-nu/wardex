# ADR-005 — Definition of done, floors and golden policy

- Status: Accepted
- Date: 2026-10-21
- Deciders: Wardex architecture
- Related: `M0#D5`, `M0#D6`, `M0#R1` to `M0#R8`, ADR-002, ADR-003

## Context

A refactoring that changes behaviour can still pass a unit test suite. Golden
tests alone can also hide a defect: when the expected output is rewritten to
match the new output, the test agrees with whatever the code now does. Coverage,
lint and security annotations decay in the same way unless a floor makes the
decay visible. Every module needs the same definition of done, or "done" means
whatever the current branch finds convenient.

The module layout also needs a decision about `contracts` and `kit`. A single
shared package would be simpler, but it would mix pure types with filesystem
and configuration I/O, and every module would depend on the I/O.

## Decision

- Every module uses the same definition of done: golden matrix green, boundary
  guard green, floors met, specs normalised, ADRs and migration steps closed.
- Golden tests are characterisation tests. They record current behaviour,
  defects included. A change to `want/` requires a `Golden-Change:` trailer
  naming the ADR or issue that justifies it.
- Coverage is measured per package. Each floor is the current coverage rounded
  down to one decimal and only rises; `make ratchet-update` refuses a decrease.
  The global floor is 40%. Moved code must reach at least 60% and new code at
  least 80%.
- Lint is a floor: `new-from-rev` is pinned to the last pre-modularisation
  release, `funlen` and `forbidigo` are enabled, and an exclusion must name the
  code it excludes. `#nosec` requires a rule code and a justification; the
  existing unjustified annotations are a counted baseline, not a licence for
  new ones.
- The boundary guard is part of the definition: a new cross-module edge fails,
  and an edge that disappears without its baseline entry being removed also
  fails.
- `contracts` and `kit` are separate. `contracts` is pure types with no I/O;
  `kit` holds primitives and may import `contracts`, never the reverse.

## Consequences

- A module cannot merge by passing only its new tests. The baseline and the
  floors have to stay green in the same commit.
- Moving code and changing behaviour do not mix. A behaviour change needs its
  own change and its own `Golden-Change` trailer.
- Floors make debt visible and slow. A refactor that adds untested code lowers
  coverage and fails until a test covers it; this is intentional.
- The split between `contracts` and `kit` adds two import paths, but keeps the
  pure type layer free of I/O and environment access.
- A baseline update is a reviewable file change, not an invisible waiver.

## Alternatives rejected

- **A single `contracts` package without `kit`.** Rejected because it would put
  `Load`, `ApplyProfile` and environment reads beside `Decision` and `Config`,
  making every type consumer depend on I/O.
- **No coverage floors, only a global percentage.** Rejected because a large
  well-covered package can hide a new package at zero.
- **Allow golden updates without a trailer.** Rejected because the test would
  then ratify every regression.
- **Per-module definitions of done.** Rejected because the weakest definition
  would become the effective one.
