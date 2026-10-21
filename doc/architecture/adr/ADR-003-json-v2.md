# ADR-003 — JSON v2 policy and the v1 deprecation window

- Status: Accepted
- Date: 2026-10-21
- Deciders: Wardex architecture
- Related: `M0#D3`, `M1#M1-D5`, `M1#M1-D6`, `M1#M1-D7`, ADR-005

## Context

The v1 JSON output uses PascalCase keys and has no schema version. Consumers
parse it directly, including CI gates and downstream reports. Renaming keys in
place would break those consumers without warning. The modularisation also
introduces structured warnings, and a machine-readable result needs a stable
place for them.

## Decision

- v1 is frozen. Its keys, values and absence of `schema_version` do not change.
- v2 is opt-in with `--json-version v2`. It adds `schema_version: 2` and a
  top-level `diagnostics` array, which is always present and may be empty.
- v2 keys are snake_case. A reflection encoder in `pkg/contracts/schema`
  converts Go field names; explicit `json` tags are preserved and map keys are
  never rewritten.
- Enumeration values such as `Covered`, `Partial` and `Gap` stay verbatim in
  v2. Converting values is a separate decision with its own compatibility
  window.
- v1 remains the default until v3.0.0. The default flips in M7, and that change
  requires a `Golden-Change` trailer because it rewrites golden expectations.
- Only commands that support v2 accept the flag. In M1 that is `assess`; the
  other commands continue to reject the unknown flag.

## Consequences

- Consumers can migrate on their own schedule; the v1 contract remains a
  supported interface for the whole v2 line.
- Every emitting command carries two output paths until v3.0.0. Golden cases
  freeze both, so a change to either is visible.
- The reflection encoder needs conformance tests for acronyms, explicit tags,
  `omitempty` and data maps whose keys must remain untouched.
- `diagnostics` in v2 is additive. Until each module converts its warning
  sites, some warnings remain only on stderr; the schema does not pretend
  otherwise.

## Alternatives rejected

- **Change v1 keys in place.** Rejected because it breaks every existing
  consumer without a version signal.
- **A token post-processor over v1 output.** Rejected because it cannot
  distinguish struct keys from data keys in maps; it would corrupt values such
  as CVE identifiers.
- **Per-module DTOs.** Rejected because the DTOs duplicate the domain types and
  drift from them.
- **Make v2 the default immediately.** Rejected because it turns an opt-in
  migration into a breaking release before v3.0.0.
- **Convert enumeration values in v2.** Deferred: it is a second compatibility
  decision, not part of the key-format change.
