# ADR-001 — Module order and dependency direction

- Status: Accepted
- Date: 2026-10-21
- Deciders: Wardex architecture
- Related: `M0#D1`, `M0#D10`

## Context

Wardex is a single Go module whose packages grew around the commands that use
them. Moving the whole repository at once would mix file moves with behaviour
changes, and a failed step would leave `main` uninstallable. The modules have a
real dependency direction: the gate consumes regulatory artefacts, the
regulatory module consumes assessment results, and every module needs the shared
contracts and kit. `accept/cli` imports `art14`, so the gate cannot precede the
regulatory module without a temporary back-edge.

## Decision

The order is:

0. baseline (`mod/0-baseline`);
1. contracts;
2. assess;
3. regulatory;
4. gate;
5. integrity.

The mechanical `/v3` module-path change (ADR-006) sits between M0 and M1.
`adapters` and `facade` are not phases: they grow with each module and always
depend on the modules below them. Each module is delivered on `mod/<n>-<id>`
and merges into `main` when its acceptance criterion closes. Branches are not
stacked.

## Consequences

- `main` remains installable after every module merge, which is what makes the
  release cadence and the golden baseline meaningful.
- The gate waits for the regulatory module even though some gate work could
  start earlier. The wait removes an import cycle and a temporary facade.
- The order is dependency order, not runtime order. A future reader cannot
  infer the order from the CLI's call graph.
- The boundary guard records the remaining cross-module edges; each module
  removes its own entries as it migrates.

## Alternatives rejected

- **Order by runtime use (gate first).** Rejected because `pkg/accept/cli`
  imports `pkg/art14`. Gate first would either duplicate Art14 logic or create a
  back-edge that the boundary guard would have to baseline indefinitely.
- **One large modularisation branch.** Rejected because a failed merge would
  leave no installable baseline and because it mixes moves, behaviour changes
  and review concerns.
- **Contracts after the feature modules.** Rejected because assess, regulatory,
  gate and integrity would first move types into their own packages and then
  move them again into contracts.
