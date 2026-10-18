# Regulatory context — NIS2

This document records what the Wardex does and does not establish with respect
to the NIS2 obligations it touches. It is a traceability matrix and a statement
of its own limits. It is not legal advice, and it does not certify conformity
for anyone.

The distinction that governs everything below: **the producer of a compliance
record may be any tool; custody of that record may not live inside the audited
perimeter.** Every artefact the Wardex writes is sealed with keys held by the
entity being audited. Against a third party that is tamper-evident. Against
the board that produced the evidence it is a diary, not proof — whoever
computes the digest can recompute it over altered material. Integrity against
the operator comes from external custody (see `doc/architecture/CRYPTO_ARCHITECTURE.md`
§7 on the 3CP tool provenance attestation), never from anything the Wardex does
locally.

## Article-level traceability

| Obligation | What it requires | What Wardex produces | Verified by |
|---|---|---|---|
| **Art. 20(1)** — accountability of the management body | The management body approves the risk-management measures, supervises their implementation, and can be held liable for infringements. Delegating execution is legitimate; delegating responsibility is not. | A sealed configuration (`.wexstate`, hash bound to the policy in force) as the artefact of approval, and signed risk acceptances carrying author, policy version and timestamp. | `wardex config seal` / `config hash`; `wardex accept verify`; chained audit log |
| **Art. 21(2)(b)** — incident handling | Procedures to detect, respond to and mitigate significant incidents. | The gate pipeline emits its own execution record: every evaluation produces a chained audit entry, and an actively exploited vulnerability forces a hard stop (exit 12) that no risk acceptance can override. | `wardex evaluate`; `wardex audit verify-chain`; exit code contract in `doc/operations/EXIT_CODES.md` |
| **Art. 21(2)(f)** — evaluating effectiveness | Policies and procedures for assessing whether the measures work. This is a meta-obligation: the entity must know whether what it does functions. | Reproducible gap and coverage output, so effectiveness can be compared across runs rather than asserted. `tools/verify-reproducible` enforces reproducibility of the binary; report ordering is pinned by tests. | `wardex assess`; `pkg/analyzer/determinism_test.go`; `make reproducible` |
| **Art. 23(4)** — staged notification | Early warning within 24 hours, notification within 72 hours with an initial severity and impact assessment, final report within one month. Each element is a claim about the entity's own records. | `wardex art14` generates the artefact and computes each deadline from the awareness timestamp, preserving both. The early warning is an alert, not an investigation; the artefact records what is known at that moment. | `wardex art14`; `pkg/art14/art14gen.go` window constants |

## What this mapping does not establish

These limits are the reason the document exists. Without them a matrix reads as
a claim.

1. **No NIS2 conformity is asserted or certified.** The Wardex records
   measurements and decisions. Whether those records satisfy any obligation is a
   determination for the entity and its authority.

2. **Reproducibility is not integrity.** They are orthogonal. Reproducibility
   answers "would the same process give the same result?"; integrity answers
   "is this the record that was produced, unaltered, by whom?" Pinning a digest
   of a CI tool gives the first and says nothing about the second. Only
   external custody gives the second.

3. **Anchoring is opt-in and external.** The Wardex produces records and can
   anchor them. Verification without the operator's cooperation requires the
   anchored chain to exist and to be reachable. If it is not anchored, the
   evidence does not leave the perimeter, whatever the local hashes say.

4. **Coverage is not the same as conformity.** A control marked `covered`
   reflects a declared mapping between a documented control and an implemented
   one. It is evidence of a claim, not adjudication of a claim.

5. **A decision that leaves no artefact was not a decision.** Conversely, the
   existence of an artefact is not proof that the underlying activity happened
   as recorded. The record establishes what the tool observed and decided.

## Portuguese transposition

The NIS2 Directive (EU) 2022/2555 is transposed in Portugal by Decreto-Lei
n.º 125/2025, of 4 December, which approves the *Regime Jurídico da
Cibersegurança*, with the CNCS as national authority. Article-level obligations
below are cited against the directive, not against the national diploma;
confirm the corresponding national provision before relying on it.

## Related documents

- `doc/architecture/CRYPTO_ARCHITECTURE.md` — key handling, canonical encoding,
  immutable storage, and the 3CP tool provenance attestation
- `doc/operations/EXIT_CODES.md` — the exit code contract that CI depends on
- `doc/architecture/TERMINAL_UI.md` — the separation between machine-oriented
  output and human presentation
