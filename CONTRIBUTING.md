# Contributing to wardex

Thank you for your interest in contributing! This document outlines the process for contributing to this project.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### [WARN] Contributor Licence Agreement (CLA)

Wardex operates under a dual-licensing model (AGPL-3.0 and Commercial). To protect the project's IP and enable commercial sublicensing, all contributors must sign a Contributor Licence Agreement (CLA).

**You do not need to sign the CLA to use Wardex**, only to contribute code.

When you open your first Pull Request, the `@cla-assistant` bot will comment with a link to sign the [CLA](doc/governance/CLA.md). You only need to sign this once. PRs cannot be merged until the author has signed the CLA.

### Third-Party-Based Contributions

Per the CLA (`doc/governance/CLA.md §4(b)`), any contribution that **includes or is based on work created by a third party** must:

1. Disclose this in the Pull Request body, identifying the third party and the applicable licence; and
2. Add (or update) the corresponding entry in [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md), including the upstream reference and licence.

Design patterns, algorithms, and protocols do not require permission to re-implement, but honest provenance is mandatory — this is part of the Guardian Audit Trail culture.

### Reporting Bugs

- Search existing issues before opening a new one.
- Include a minimal reproducible example.
- Describe the expected vs. actual behaviour.

## Gitflow Strategy (main + dev)

Wardex strictly uses a **Simplified Gitflow** model (`main` + `dev` branches) to maintain project hygiene, historically granulated commits, and high security standards. We do *not* use long-lived `test` or `audit` branches.

### Branch Architecture

1. **`main` (Production / Audit Trail)**
   - Always pristine, deployable, and cryptographically sound.
   - Contains only tagged production releases (e.g., `v1.7.0`).
   - Direct commits are **prohibited**. All code arrives via Pull Requests from `dev`.
   - Used as the ultimate source of truth for an auditor of any supported framework.

2. **`dev` (Integration / Pre-Release)**
   - The primary working branch.
   - All feature branches branch off `dev` and merge back into `dev`.
   - Once `dev` reaches a stable milestone, a Release PR is opened from `dev` into `main`.

3. **Feature Branches (`feat/*`, `fix/*`, `docs/*`, `chore/*`)**
   - Short-lived, ephemeral branches branched off `dev`.
   - Deleted immediately after being squashed/merged into `dev`.

### Submission Pipeline (Project Hygiene)

1. Branch off `dev`: `git checkout -b feat/my-feature dev`
2. Commit your changes using [Conventional Commits](https://www.conventionalcommits.org/) (e.g., `feat: implement epss enrichment`).
3. Run local security and hygiene checks:
   - `golangci-lint run ./...`
   - `gosec ./...`
   - `go test -race ./...`
4. Push your branch and open a Pull Request targeting the **`dev`** branch (NOT `main`).
5. GitHub Actions CI will re-run all linting, static analysis, and unit tests. The PR cannot be merged if any check fails or coverage drops.
6. Once merged, the feature branch must be deleted.

## Commit Style (Conventional Commits)

| Prefix     | When to use                                  |
|------------|----------------------------------------------|
| `feat:`    | New feature                                  |
| `fix:`     | Bug fix                                      |
| `docs:`    | Documentation only                           |
| `refactor:`| Code change that neither fixes nor adds      |
| `test:`    | Adding or fixing tests                       |
| `chore:`   | Maintenance, dependency updates, build tasks |
| `ci:`      | CI/CD changes                                |

Example: `feat: add support for YAML config replay`

### Attribution Trailers

A `Co-authored-by:` trailer is attribution. It records who contributed to the
work. It is not a review, a sign-off or an authorisation, and it does not make
the party named responsible for the commit.

Adding a trailer names a party to work they may never have seen. Do not add one
for another person or organisation without their agreement. A tool that adds
such a trailer by default has been authorised by nobody.

A trailer naming an AI assistant is attribution in the same sense as any other
trailer. This repository neither requires one nor infers consent from one.

CI enforces this on new work. `tools/check-attribution` fails the build when a
pull request adds a `Co-authored-by` trailer naming a coding assistant, and it
reads only the range the pull request proposes to merge, so it says nothing
about history that predates the check. Treat a failure as a prompt to look, not
as proof that nothing is wrong: the deny list is matched against free text and
does not resist a deliberate change.

**History is not rewritten to remove a trailer.** Rewriting is reserved for
correcting content — credentials, personal data, malicious code. Where a
trailer was added without the agreement of the party named, remove it going
forward and record that in the pull request rather than rewriting silently.

## Testing Requirements

- All new code must include unit tests.
- Run `make test` before submitting.
- Coverage must not regress.
- Tests must pass with `-race` flag.

## Code Review

- All PRs require at least one review.
- Address all comments before merging.
- Keep PRs focused — one feature/fix per PR.

## Development Setup

```bash
git clone https://github.com/had-nu/wardex.git
cd wardex
go mod download
make test
```

---

_Thank you for contributing to wardex!_
