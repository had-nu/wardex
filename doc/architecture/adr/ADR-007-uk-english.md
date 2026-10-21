# ADR-007 — UK English as the project language

- Status: Accepted
- Date: 2026-10-21
- Deciders: Wardex architecture
- Related: `M0#D13`, `M0#P0.3`, ADR-005

## Context

The repository grew with Portuguese prose beside English prose, and some
user-facing strings mixed the two. A project that is published and reviewed in
one language needs one vocabulary: otherwise the same concept appears under
several names, tests freeze inconsistent messages, and contributors cannot tell
which spelling is normative.

The migration cannot be a blanket rename. Go identifiers and published JSON
keys are part of the compatibility contract. Changing them would break callers
and golden tests for a spelling preference rather than a behaviour change.

## Decision

- UK English is the project language for prose, comments, documentation,
  user-facing messages, warnings and report text.
- Existing Go identifiers, public API names and published schema values are not
  renamed for spelling in M0. New identifiers use UK English.
- The vocabulary is fixed: `module` is the architectural unit, `component` is a
  deliverable within a module, `package` is a Go package, and `Go module` is
  the `go.mod` unit. `baseline` is the frozen reference state. The source of
  truth is `doc/specs/glossary.yaml`.
- Historical specs are archived as `legacy-pt` with an English abstract. They
  are not rewritten in place; their status records what they are.
- The user-facing migration (CLI help, errors, warnings, dashboards, Markdown
  and HTML reports, templates and test messages) runs before the baseline is
  cut. The wider documentation migration runs in parallel and does not block
  M0.
- A language check belongs to the parallel workstream. M0 provides the
  glossary and the vocabulary, not a second implementation of the checker.

## Consequences

- Golden output changes once, during the baseline migration, and is then
  frozen. The change is recorded before `v2.7.0-rc.1`, so later modules inherit
  English expectations rather than translating them mid-migration.
- Contributors pay a small cost for UK spelling and the controlled vocabulary;
  reviewers can point at the glossary instead of arguing style.
- Public JSON keys and Go identifiers keep their current spelling. A future
  rename needs its own compatibility decision, not a language decision.
- Historical documents remain readable in their original language, with an
  English abstract as the entry point.

## Alternatives rejected

- **Portuguese-first documentation.** Rejected because the published product,
  release notes and CI messages are already predominantly English and the
  user-facing contract is English.
- **Per-file language choice.** Rejected because it preserves the vocabulary
  split and makes the glossary unenforceable.
- **US English.** Rejected because the project's established spelling and the
  glossary use UK English.
- **Rename identifiers and schema values in the same migration.** Rejected
  because it turns a prose migration into a breaking API change and obscures
  the golden diff.
