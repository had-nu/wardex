# Contributing to wardex

Thank you for your interest in contributing! This document outlines the process for contributing to this project.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### ⚠️ Contributor Licence Agreement (CLA)

Wardex operates under a dual-licensing model (AGPL-3.0 and Commercial). To protect the project's IP and enable commercial sublicensing, all contributors must sign a Contributor Licence Agreement (CLA).

**You do not need to sign the CLA to use Wardex**, only to contribute code.

When you open your first Pull Request, the `@cla-assistant` bot will comment with a link to sign the [CLA](doc/CLA.md). You only need to sign this once. PRs cannot be merged until the author has signed the CLA.

### Reporting Bugs

- Search existing issues before opening a new one.
- Include a minimal reproducible example.
- Describe the expected vs. actual behaviour.

### Submitting Pull Requests

1. Fork the repository.
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Commit your changes following [Conventional Commits](https://www.conventionalcommits.org/).
4. Push your branch and open a Pull Request.

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
git clone https://github.com/github.com/had-nu/wardex.git
cd wardex
go mod download
make test
```

---

_Thank you for contributing to wardex!_
