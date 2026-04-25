# Wardex: Agentic AI Git Flow & Quality Guide

This document defines the mandatory workflow and quality standards for any AI Agent contributing to the Wardex repository. Adherence to these rules is critical to maintaining a production-ready, clean, and professional codebase.

---

## 1. Top-Level Directives (Non-Negotiable)

- **NEVER use emojis**: Do not use emojis in commit messages, documentation, console outputs, or code comments. Use text markers like `[OK]`, `[FAIL]`, `[WARN]`, or `[INFO]` instead.
- **Sanitization First**: Before every push, perform a "Pente Fino" (fine-tooth comb) check to ensure no transient artifacts, research notes, or POC data have entered the tracking index.
- **Conventional Commits**: Use the prefix `feat:`, `fix:`, `docs:`, `chore:`, or `test:` followed by a clear, lowercase description.

---

## 2. Branching & Synchronization

Wardex follows a simplified Git Flow:
- **main**: The stable, production-ready branch. All releases are tagged from here.
- **dev**: The integration branch. New features are developed here before being merged to main.

**Agent Workflow:**
1.  Verify the current branch and local state.
2.  Perform changes.
3.  Commit to `main` (if authorized for direct hotfixes/doc updates) or `dev`.
4.  **MANDATORY**: Whenever `main` is updated, immediately synchronize `dev` using:
    `git push origin main:dev --force`

---

## 3. Pre-Push Checklist ("Pente Fino")

Before running `git push`, the Agent MUST:

1.  **Validate Compilation**: Run `go build ./...` to ensure no syntax errors.
2.  **Run Tests**: Run `go test ./...` to prevent regressions.
3.  **Audit File Tree**: Run `git status` and `git ls-files` to check for:
    - Unexpected `.md` files in root or `doc/`.
    - Python (`.py`) or JavaScript (`.js`/`.jsx`) scripts that belong in `.gitignore`.
    - JSON/YAML datasets that are not part of the official catalog or testdata.
4.  **Check Documentation**: Ensure all version references (e.g., `v1.7.2`) are consistent across `README.md` and the Playbook.

---

## 4. Documentation Standards

- **Language**: Primary documentation in Portuguese, with English versions available in `README-en.md`.
- **Tone**: Professional, technical, and executive-oriented.
- **Formatting**: Use GitHub-flavored Markdown. Use LaTeX syntax (`$$`) for mathematical formulas in `TECHNICAL_VIEW.md`.

---

## 5. Artifact Exclusion List

The following patterns MUST NOT be committed to the repository (ensure they are in `.gitignore`):
- `research/` (Datasets, raw analysis)
- `test/poc/` (Transient proof of concepts)
- `test/tuning/` (Calibration scripts)
- `test/outputs/` (Logs and temporary reports)
- `*.docx`, `*.xlsx` (Binary office documents)

---

## 6. License Integrity

Every new `.go` file MUST include the official Wardex license header:
```go
// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial
```

---
*Signed: Wardex Governance Protocol*
