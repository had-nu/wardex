# Wardex documentation

One page that says where everything is and what it is for. If a document you
need is not listed here, that is a defect in this page rather than a fact about
the repository.

## Where things live

There are four directories with documentation in them, and they do different
jobs. Confusing them was the reason this file exists.

| Path | Holds | Markdown? |
| --- | --- | --- |
| `doc/` | All prose documentation. **The only directory with prose in it.** | yes |
| `docs/` | The published website, served by GitHub Pages from the `dev` branch. | no |
| `spec/` | CDDL schemas. Machine-readable, referenced from Go comments. | no |
| `internal/` | Go packages only. No documents. | no |

`docs/` and `doc/` differ by one letter and have nothing in common beyond that.
A markdown file in `docs/` is misplaced: `doc/regulatory-context.md` sat there
until this consolidation moved it.

## Start here

| Document | What it answers |
| --- | --- |
| [README](../README.md) | What Wardex is and how to install it |
| [Onboarding](ONBOARDING.md) | How to work on this codebase |
| [Input guide](../INPUT_GUIDE.md) | What evidence the tool expects and in what shape |
| [Contributing](../CONTRIBUTING.md) | Branches, commit style, the attribution policy |
| [Security](../SECURITY.md) | Reporting a vulnerability |

## Regulatory context

| Document | What it answers |
| --- | --- |
| [Regulatory context](regulatory-context.md) | Article-level traceability for NIS2, and the limits of what that mapping claims |
| [Frameworks](../pkg/catalog) | The control catalogues, one YAML per framework. Each header names the instrument the controls were taken from. |

## Architecture

| Document | What it answers |
| --- | --- |
| [Technical view](architecture/TECHNICAL_VIEW.md) | How the system is put together |
| [Business view](architecture/BUSINESS_VIEW.md) | Why it is put together that way |
| [Engineering blueprint](architecture/ENGINEERING_BLUEPRINT.md) | Build, test and release expectations |
| [Crypto architecture](architecture/CRYPTO_ARCHITECTURE.md) | Trust chain, key envelopes, the 3CP protocol |
| [Provenance enhancement](architecture/REC_PROVENANCE_ENHANCEMENT.md) | Anchoring and timestamping |
| [Terminal UI](architecture/TERMINAL_UI.md) | Rendering contract, including what machine output must never receive |
| [Branding](architecture/BRANDING.md) | Visual assets and their sources |

## Operations

| Document | What it answers |
| --- | --- |
| [Playbook](operations/WARDEX_PLAYBOOK.md) | Running the thing day to day |
| [Trust playbook](operations/WARDEX_TRUST_PLAYBOOK.md) | Trust store, keys, verification |
| [Exit codes](operations/EXIT_CODES.md) | What each exit code means and what it commits the caller to |
| [GitHub Actions integration](operations/github-actions-integration.md) | Wiring the gate into a pipeline |

## Governance and licensing

| Document | What it answers |
| --- | --- |
| [Contributor licence agreement](governance/CLA.md) | What signing the CLA commits you to |
| [Commercial licence](governance/COMMERCIAL_LICENSE.md) | Commercial terms |
| [Gitflow and AI guide](governance/GITFLOW_AI_GUIDE.md) | Branching model and the rules for AI-assisted work |

## Specifications

Ten specifications, all of them committed. Three of these were silently
untracked until this consolidation, because an unanchored `specs/` rule in
`.gitignore` matched `doc/specs/`; a fourth sat at the repository root behind an
unanchored `SPEC-*.md` rule.

| Document | Scope |
| --- | --- |
| [Trust](specs/SPEC_wardex_trust_.md) | Trust system, certificates, key envelopes |
| [v1.9.1 schema cleanup](specs/SPEC_v1.9.1_schema_cleanup.md) | Schema decisions |
| [v1.9.2 incomplete behaviours](specs/SPEC_v1.9.2_incomplete_behaviours.md) | What was left undone, and why |
| [v2.0 CRA Article 14](specs/SPEC_wardex_v2.0_CRA_Art14.md) | Active exploit notification. Section 8 holds the deferred roadmap |
| [v2.0.1 SDLC hardening](specs/SPEC_wardex_v2.0.1_sdlc_hardening.md) | Build chain. Section 3 holds deferred provenance work |
| [v2.2.2](specs/v2.2.2-SPEC.md) | Version 2.2.2 |
| [CI/CD hardening](specs/SPEC-WARDEX-HARDEN-CORDYCPS-BASED-v2.2.2.md) | Pipeline hardening |
| [v2.5.0 Go 1.27](specs/SPEC_wardex_v2.5.0_go127_hardening.md) | Toolchain move |
| [v2.6.0 Nym patterns](specs/SPEC_wardex_v2.6.0_nym_patterns.md) | Chain unification, key envelopes, gate classes |
| [CBOR migration v2.3.0](specs/CBOR_MIGRATION_v2.3.0.md) | Migration to canonical CBOR |

## Releases

Thirty release notes in [`releases/`](releases/), from v1.1.0 to v2.6.1. The
narrative is in [CHANGELOG](../CHANGELOG.md); the upload procedure is in
[RELEASES](../RELEASES.md).

## Other reference material

| Path | What it is |
| --- | --- |
| [examples/](examples/) | A worked `wardex-config.yaml` and a NIS2 policy file |
| [benchmarks/](benchmarks/) | Recorded benchmark results |
| [assets/](assets/) | Brand images, source of the release banner |
| [ACKNOWLEDGMENTS](../ACKNOWLEDGMENTS.md) | What is drawn from where |

## Conventions for documents here

- Prose is English (UK). Identifiers are frozen: exported Go names, JSON tags,
  CSV headers, environment variables, flag names and exit-code names do not
  change spelling with the prose around them.
- A path written inside a document must resolve. Link checking is part of CI.
- A statement about where something used to live is history and stays. A
  reference to where something lives now is updated when it moves.