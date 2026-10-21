# ADR-004 — Errors, exit codes and Diagnostic

- Status: Accepted
- Date: 2026-10-21
- Deciders: Wardex architecture
- Related: `M0#D4`, `M1#M1-D4`, `M1#M1-D9`, ADR-003

## Context

Exit codes are part of the command-line contract, but they are currently
computed in several places. Some commands return literal values; others map
errors by hand. Recoverable warnings are written directly through `ui.Warnf`,
which couples library code to the terminal and gives JSON v2 no way to carry
the warning. Modularisation would spread both patterns further.

## Decision

- `pkg/contracts/exitcodes` owns the numeric contract and the sentinel errors
  that map to it. `FromError` uses `errors.Is` and returns the documented code;
  unknown errors return 1 and `nil` returns 0.
- Recoverable warnings become `Diagnostic` values in the result:
  severity, stable code, current message and structured context. They are not
  errors and do not change the exit code.
- `ui.RenderDiagnostics` writes a diagnostic with the same text and level as
  the warning it replaces. The owning module converts its own sites, so the
  stderr text stays byte-for-byte identical.
- Error codes are `<module>.<theme>.<cause>`, lowercase, and stable once
  published.
- The existing numeric codes stay: 0, 1, 3, 4, 5, 6, 10, 11, 12 and 13. Code 2
  remains reserved by the contract test; the documented CPL exception in
  `cmd/audit` is a known defect frozen by the G8 golden and decided in M5.
- JSON v2 renders diagnostics at the top level. v1 does not change.

## Consequences

- Library code no longer writes warnings to the terminal; the adapter chooses
  the destination and the format.
- Each module migration includes converting its warning sites. Until then, the
  warning remains on stderr and is absent from v2 diagnostics.
- A new exit code requires a contract test change and a spec decision; it
  cannot be invented in a command.
- The known code-2 inconsistency remains visible rather than being silently
  normalised. Changing it would break users of the documented CPL behaviour.

## Alternatives rejected

- **Keep ad hoc exit codes in each command.** Rejected because the same
  condition would produce different codes in different adapters.
- **Turn warnings into errors.** Rejected because a warning must not change the
  outcome or the exit status.
- **Write diagnostics through a global logger.** Rejected because it hides the
  dependency and makes tests and library callers share global state.
- **Panic and recover at the command boundary.** Rejected because it loses the
  error chain and makes exit-code mapping unreliable.
