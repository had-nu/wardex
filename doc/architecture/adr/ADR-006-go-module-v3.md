# ADR-006 — Go module path to `/v3`

- Status: Accepted
- Date: 2026-10-21
- Deciders: Wardex architecture
- Related: `M0#D7`, ADR-001, ADR-002

## Context

The module is published as `github.com/had-nu/wardex/v2`, and the next release
line is v3.0.0. Go requires a `/v3` suffix in the module path for a v3 release;
without it, `go install` and the module proxy treat the release as a v2
release. The suffix changes every internal import, the README examples and
`examples/sdk`.

Doing the rewrite inside M1 would mix a mechanical import change with the first
code moves. Doing it only at M7 would leave the whole modularisation on the v2
path and produce no installable v3 module during the migration. Doing it never
would make the v3 release impossible to consume as a Go module.

## Decision

- A dedicated mechanical PR changes the module path from
  `github.com/had-nu/wardex/v2` to `github.com/had-nu/wardex/v3`.
- The PR runs after M0 closes and before M1 starts. It changes imports, the
  README and `examples/sdk`, and nothing else.
- The golden harness builds the same binary from the new path; the expected
  output does not change.
- The Docker and Action plumbing is already removed in M0-P0.5, so there is no
  container or Marketplace path to rewrite.
- v2 releases remain available under the old path. The v3 path is a new major
  version, not a rename of the v2 module.

## Consequences

- Every internal import changes once, in a commit that is easy to review and
  easy to revert.
- Downstream users must switch to `github.com/had-nu/wardex/v3` when they move
  to v3. The v2 line keeps its own releases.
- CI, the golden harness and `go install` examples use the v3 path from M1
  onward.
- The mechanical PR has no behaviour change, so a golden failure in that PR is
  an import mistake, not an intended output change.

## Alternatives rejected

- **Raise the path inside M1.** Rejected because it mixes a repository-wide
  import rewrite with the contracts and kit moves, making both harder to
  review.
- **Raise the path only at M7.** Rejected because every module would migrate on
  the v2 path and the final release would need a second repository-wide
  rewrite.
- **Do not raise the path.** Rejected because a v3.0.0 module cannot be
  installed correctly without `/v3`.
- **Publish v3 from a separate repository.** Rejected because it splits the
  history and the release automation for no benefit.
