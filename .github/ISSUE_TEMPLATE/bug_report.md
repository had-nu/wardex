---
name: Bug Report
about: Report a bug to help improve Wardex
title: "[BUG] "
labels: bug
assignees: had-nu
---

## Describe the Bug
A clear and concise description of what the bug is.

## Reproduction Steps

```bash
# Include the exact command(s) that trigger the bug
wardex evaluate --gate vulns.yaml
```

## Expected Behaviour
What you expected to happen.

## Actual Behaviour
What actually happened (include full error output).

## Environment
- Wardex version: <!-- e.g. v2.1.2, dev -->
- Go version: <!-- output of `go version` -->
- OS: <!-- e.g. Linux, macOS -->
- Config file: <!-- attach or describe relevant config sections -->

## Additional Context
- [ ] Can you reproduce with `--dry-run`?
- [ ] Does the issue occur with sealed config (`.wexstate`)?
- [ ] Is this blocking a CI pipeline?
