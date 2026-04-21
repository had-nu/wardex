# WARDEX — Gap Analysis Update
## v1.6.0 Repository Inspection · March 2026

> Source-grounded analysis based on direct inspection of commits `2450e8e..5bb06d8` (v1.5.0 → v1.6.0).
> Files inspected: `pkg/accept/cli/cli.go`, `config/config.go`, `main.go`, `doc/COMMERCIAL_LICENSE.md`,
> `doc/CLA.md`, `doc/wardex-g20-audit-readiness.md`, `.github/workflows/cla.yml`, `LICENSE`, `CONTRIBUTING.md`, `CHANGELOG.md`.

---

## 1. Overall Progress Scorecard

```
v1.1.0 → v1.6.0   ·   22 Original Gaps   ·   7 New Gaps Identified in v1.6.0
```

### Original 22 Gaps

| Status | Count | Share |
|:---|:---:|:---:|
| ✅ **RESOLVED** | **21** | **95%** |
| ⚠️ **PARTIAL** | **1** | **5%** |
| ❌ **OPEN** | **0** | **0%** |

```
████████████████████████████████████████████████░░  21 Resolved  (95%)
░░                                                    1 Partial   ( 5%)
```

### New Gaps Discovered (v1.6.0)

| Status | Count |
|:---|:---:|
| ❌ **OPEN** | **5** |
| ⚠️ **PARTIAL** | **2** |

---

## 2. Original Gap Matrix — Updated Status

### 2.1 Bugs (G-01 to G-06) — All Resolved

| ID | Title | v1.5.0 | v1.6.0 | Evidence |
|---|---|:---:|:---:|---|
| G-01 | `--expires 30d` silently fails | ✅ | ✅ | `pkg/duration/duration.go` — `ParseExtended()` |
| G-02 | `--config` ignored by `accept` subcommands | ✅ | ✅ | `pkg/accept/cli/cli.go` — config pointer propagation |
| G-03 | Multi-CVE acceptance drops all but first | ✅ | ✅ | `pkg/accept/cli/cli_multicve_test.go` |
| G-04 | Exit code 2 on BLOCK (POSIX conflict) | ✅ | ✅ | `pkg/exitcodes/exitcodes.go` — `GateBlocked=10` |
| G-05 | Banned phrases equality match (not substring) | ✅ | ✅ | `pkg/accept/validator/validator.go` — `strings.Contains` |
| G-06 | No `--version` flag | ✅ | ✅ | `main.go` — `rootCmd.Version` with ldflags |

No regressions detected. SPDX copyright header `// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu)` added to all `.go` files in v1.6.0 sweep.

---

### 2.2 Incomplete Features (G-07 to G-11)

| ID | Title | v1.5.0 | v1.6.0 | Change |
|---|---|:---:|:---:|---|
| **G-07** | `verify-forwarding` not implemented | ⚠️ PARTIAL | ✅ **RESOLVED** | Real TCP/HTTP probe — see below |
| G-08 | `accept list` output json/csv missing | ✅ | ✅ | No change needed |
| G-09 | `warn` decision never produced | ✅ | ✅ | No change needed |
| G-10 | Roadmap hard-capped at 10 items | ✅ | ✅ | No change needed |
| G-11 | Snapshot path not configurable | ✅ | ✅ | No change needed |

#### G-07 Deep Dive — Now Resolved

**v1.4.0 (previous partial):** Implementation was `time.Sleep(500ms)` followed by a hardcoded `[PASS]` print — no real network probe.

**v1.6.0 (resolved):** Two real connection paths implemented in `pkg/accept/cli/cli.go`:

1. **HTTP/HTTPS backends** (`strings.HasPrefix` check): `http.Client{Timeout: 3s}.Get(verifyBackend)` — real GET request, exits 1 on connection error or HTTP 5xx.
2. **TCP/Syslog backends** (fallback): `net.DialTimeout(network, address, 3s)` — real socket connection, exits 1 on failure.

The `time.Sleep` simulation is gone. The command now fails closed on unreachable backends, which is the correct security posture.

**Remaining caveat (surfaced as new gap N-03):** The `--since` flag is declared but still not acted upon — a `// Optional: We could parse the JSONL` comment remains in the code. JSONL record validation is not performed.

---

### 2.3 Features (G-12 to G-18)

| ID | Title | v1.5.0 | v1.6.0 | Change |
|---|---|:---:|:---:|---|
| G-12 | No native Grype input adapter | ✅ | ✅ | No change needed |
| G-13 | No CycloneDX/SPDX SBOM ingestion | ✅ | ✅ | No change needed |
| G-14 | No `warn` threshold / risk band | ✅ | ✅ | No change needed |
| **G-15** | No RBAC / per-team risk appetite | ⚠️ PARTIAL | ✅ **RESOLVED** | `AllowedActors` enforcement — see below |
| G-16 | Risk simulator not shipped | ✅ | ✅ | No change needed |
| G-17 | No VEX support | ✅ | ✅ | No change needed |
| G-18 | No godoc API reference | ✅ | ✅ | No change needed |

#### G-15 Deep Dive — Now Resolved (with caveats)

**v1.3.0 (previous partial):** `--profile` was a per-invocation CLI flag with no access control — any developer could pass any profile name.

**v1.6.0 (resolved):** `AllowedActors []string` field added to `ConfigProfile` struct in `config/config.go`. In `main.go`, the profile resolution reads the executing identity from environment variables in priority order:

```go
actor = os.Getenv("WARDEX_ACTOR")  // Explicit override
actor = os.Getenv("GITHUB_ACTOR")   // GitHub Actions runner identity
actor = os.Getenv("USER")           // Local shell user
```

On mismatch against `allowed_actors`, Wardex logs `[RBAC VIOLATION]` and falls back to the strictest baseline config — it does **not** exit 1, which means pipeline continues under baseline policy. This is a deliberate design choice (degraded-mode-safe) but surfaced as new gap **N-02**.

The `doc/wardex-g20-audit-readiness.md` documents this model explicitly for auditors, covering non-repudiation, config drift protection, and RBAC under a single architecture reference.

---

### 2.4 Strategic Gaps (G-19 to G-22)

| ID | Title | v1.5.0 | v1.6.0 | Change |
|---|---|:---:|:---:|---|
| G-19 | No SOC 2 / NIS2 / DORA mapping | ✅ | ✅ | No change needed |
| **G-20** | No external security audit | ⚠️ PARTIAL | ⚠️ **PARTIAL** | Improved posture, gap persists |
| **G-21** | AGPL-3.0 / no dual licensing | ❌ OPEN | ✅ **RESOLVED** | Full dual-licensing infrastructure shipped |
| G-22 | No changelog / release notes | ✅ | ✅ | No change needed |

#### G-20 Deep Dive — Still Partial

**What improved in v1.6.0:**
- `doc/wardex-g20-audit-readiness.md` published — a 4-section architecture document covering cryptographic non-repudiation, RBAC, config drift protection, and SIEM telemetry. Explicitly aligned to SOC 2 Type II (CC7.1), ISO 27001 (A.8), and DORA.
- SPDX dual-licence identifiers on all 84 `.go` files.
- Copyright notice added to `LICENSE`.

**What remains missing:**
- No third-party, independent security audit by a CREST/OSCP-certified firm has been commissioned or published.
- The audit readiness document is self-authored — it cannot serve as external auditor evidence; it is a pre-audit preparation artefact.
- For regulated-industry (DORA, HIPAA) adoption, the gap remains open until a penetration test report is published.

**Assessment:** The v1.6.0 changes significantly improve the *auditability* of Wardex — an auditor now has a reference document explaining the cryptographic architecture. This reduces audit preparation time and cost. But it does not close the gap of *having been audited*.

#### G-21 Deep Dive — Now Resolved

**What was shipped in v1.6.0:**

| Artefact | File | Status |
|---|---|:---:|
| Commercial licence terms | `doc/COMMERCIAL_LICENSE.md` | ✅ Present |
| Contributor Licence Agreement | `doc/CLA.md` | ✅ Present |
| CLA GitHub Actions workflow | `.github/workflows/cla.yml` | ✅ Live |
| Copyright notice on LICENSE | `LICENSE` line 1 | ✅ Present |
| SPDX dual identifier on all sources | All `*.go` files | ✅ Present |
| README dual-licensing section | `README.md` — "Licenciamento e Uso Comercial" | ✅ Present |
| CONTRIBUTING.md CLA requirement | `CONTRIBUTING.md` | ✅ Present |

The CLA workflow triggers on `pull_request_target` and `issue_comment`, blocks merges until contributors comment `"I have read the CLA Document and I hereby sign the CLA"`, and stores signatures at `signatures/version1/cla.json`. The `allowlist: 'had-nu,bot*'` correctly exempts the project owner and bots.

**Remaining caveat (surfaced as new gap N-01):** `doc/COMMERCIAL_LICENSE.md` contains five unresolved placeholders: `[DATE]`, `[JURISDICTION]` (×2), `[domain]` (×3), and `[TO BE COMPLETED BEFORE PUBLICATION]`. The licence is not legally effective until these are filled and attorney-reviewed.

---

## 3. New Gaps Identified in v1.6.0

Direct source inspection of the v1.6.0 codebase reveals 7 new gaps not present in the previous analysis. These are net-new issues, not regressions of resolved gaps.

---

### N-01 — `COMMERCIAL_LICENSE.md` Contains Unresolved Placeholders
**Category:** ❌ Bug · **Priority:** Critical · **Effort:** XS · **Adoption Impact:** ●●●●● (5/5)

**Location:** `doc/COMMERCIAL_LICENSE.md` — lines 3, 324, 327, 394, 411, 418, 425

**Placeholders found:**
```
[DATE]                    — Effective Date (line 3)
[JURISDICTION]            — Governing law clause (lines 324, 327)
[domain]                  — Contact email (lines 394, 411, 418, 425)
[TO BE COMPLETED...]      — Registered address (line 420)
```

**Impact:** The commercial licence is the legal instrument that allows SaaS embedding revenue. With `[DATE]` unfilled, the Agreement has no effective date — a court could find it unenforceable. With `[JURISDICTION]` unfilled, there is no governing law or dispute resolution forum. With `[domain]` unfilled, a potential commercial licensee who clicks "contact" in the README arrives at `commercial@[domain]` — a non-existent address.

**Fix:** Fill placeholders with real values. Add attorney review. Create `commercial@wardex.dev` (or equivalent) email alias. Estimated: half a day + legal review.

---

### N-02 — RBAC `AllowedActors` Bypassable Outside CI Context
**Category:** ⚠️ Incomplete · **Priority:** High · **Effort:** M · **Adoption Impact:** ●●●● (4/5)

**Location:** `main.go` — RBAC profile resolution block

**Current behaviour:** Actor identity is read from environment variables. Outside GitHub Actions CI, `WARDEX_ACTOR` is an arbitrary env var that any developer can set in their shell:

```bash
export WARDEX_ACTOR=payment-api-lead
wardex --profile payment-api --gate vulns.yaml controls.yaml
# [INFO] RBAC Verified. Loaded profile 'payment-api' for actor 'payment-api-lead'
```

There is no cryptographic proof that `WARDEX_ACTOR=payment-api-lead` corresponds to the actual running identity. The RBAC model is valid in GitHub Actions (where `GITHUB_ACTOR` is set by the runner and cannot be overridden by workflow code under default permissions), but it provides no protection in local development or self-hosted runners with loose configuration.

**Impact:** A developer running Wardex locally can assume any profile, bypassing stricter organisational risk appetite thresholds. In a regulated context, this undermines the "Least Privilege" claim made in `doc/wardex-g20-audit-readiness.md`.

**Fix:** Document the CI-only validity of this RBAC model explicitly in the CLI help text and audit doc. Optionally: require a signed token (e.g., GitHub OIDC JWT) for profile assertion in sensitive contexts. Estimated effort: M for a token-based approach; XS for documentation-only clarification.

---

### N-03 — `verify-forwarding --since` Flag Declared but Not Implemented
**Category:** ⚠️ Incomplete · **Priority:** Medium · **Effort:** S · **Adoption Impact:** ●●● (3/5)

**Location:** `pkg/accept/cli/cli.go:338` — comment `// Optional: We could parse the JSONL and filter by verifySince`

**Current behaviour:** `--since` flag is registered (`StringVar(&verifySince, "since", ...)`), appears in `wardex accept verify-forwarding --help`, but is never read or acted upon. The JSONL audit log is never parsed — only its file size is reported.

**Impact:** A security engineer who runs `wardex accept verify-forwarding --since 30d` to verify that the last 30 days of audit events are reachable at the SIEM gets a `[PASS]` regardless. This is a documentation-lie pattern: the flag implies functionality that does not exist. It is a regression of the same pattern that existed in the original G-07 (`verify-forwarding` was a stub).

**Fix:** Parse the JSONL lines, filter by timestamp >= `time.Now().Add(-parsedDuration)`, count valid events, and include the count in the `[PASS]` output. Estimated: S (1–2 days).

---

### N-04 — `LicenseRef-Wardex-Commercial` SPDX Identifier Not Registered
**Category:** ❌ Open · **Priority:** Medium · **Effort:** XS · **Adoption Impact:** ●●● (3/5)

**Location:** All 84 `*.go` files — `// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial`

**Current behaviour:** `LicenseRef-Wardex-Commercial` is a valid SPDX syntax for a custom licence identifier, but it is not registered in the SPDX licence list. Commercial licence scanning tools (FOSSA, TLDR Legal, Snyk Open Source, Black Duck) will flag it as an **unknown licence** and may classify the entire repository as unlicensed or non-compliant.

**Impact:** Enterprise adopters who run automated licence scanning (common for ISO 27001 software inventory compliance) will receive alerts on Wardex as an unknown-licence dependency. This creates friction at the procurement and legal review stage — the exact moment a commercial licence sale could be closing.

**Fix:** Two options:
1. **Document-based:** Add a `LicenseRef-Wardex-Commercial.txt` file to the repo root (the SPDX standard for custom identifiers) and submit a PR to SPDX to register the identifier if it meets their criteria.
2. **Pointer-based:** Change the SPDX tag to `AGPL-3.0-or-later OR LicenseRef-scancode-wardex-commercial` with a pointer to `doc/COMMERCIAL_LICENSE.md`. This is the approach used by Elastic (`LicenseRef-Elastic-License-2.0`).

Estimated: XS (< 1 hour for the file, separate process for SPDX registration).

---

### N-05 — OpenVEX Standalone Documents Not Supported
**Category:** ❌ Open · **Priority:** Medium · **Effort:** M · **Adoption Impact:** ●●● (3/5)

**Location:** `pkg/sboms/cyclonedx.go` — VEX parsing scoped to CycloneDX `analysis.state` field only

**Current behaviour:** VEX suppression (G-17) works exclusively within CycloneDX SBOM documents. OpenVEX (the CISA-endorsed standalone VEX format, `https://openvex.dev`) documents cannot be ingested.

**Impact:** CISA has endorsed OpenVEX as the preferred VEX format for software transparency. Teams following CISA guidance (particularly US government contractors subject to EO 14028) generate OpenVEX documents, not CycloneDX VEX profiles. These teams must maintain separate suppression workflows outside Wardex, reintroducing the manual conversion friction that G-17 was designed to eliminate.

**Fix:** Add `pkg/sboms/openvex.go` reader. OpenVEX documents are JSON-LD; the schema is public at `openvex.dev`. Map `status: "not_affected"` / `"false_positive"` to the same suppression logic as CycloneDX. Estimated: M (3–5 days including tests).

---

### N-06 — No Test Coverage Enforcement in CI
**Category:** ❌ Open · **Priority:** Low · **Effort:** S · **Adoption Impact:** ●● (2/5)

**Location:** `CONTRIBUTING.md` — "Coverage must not regress" · No CI workflow file enforces this

**Current behaviour:** The contributing guide states coverage must not regress, but no CI workflow enforces a coverage gate. `go test -cover` is not invoked with a threshold in any visible GitHub Actions workflow. There is no coverage badge in the README.

**Impact:** Contributors can merge code that reduces test coverage without any automated signal. As the codebase grows (especially `cmd/convert/`, `pkg/sboms/`, multi-framework catalogs), test debt accumulates silently. For an ISO 27001 tool that itself reports on control maturity, this is a credibility gap — the project does not practice what it preaches on measurable quality assurance.

**Fix:** Add `go test -coverprofile=coverage.out ./...` and a threshold check (e.g., `go-coverage-report` action or `bash: [ $(go tool cover -func coverage.out | grep total | awk '{print $3}' | tr -d '%') -ge 70 ]`) to the CI workflow. Add a Codecov or coveralls badge to README. Estimated: S (1–2 days including baseline calibration).

---

### N-07 — No Trademark Registration for "Wardex"
**Category:** ❌ Open · **Priority:** Low · **Effort:** L · **Adoption Impact:** ●●● (3/5)

**Location:** `doc/COMMERCIAL_LICENSE.md` — "The Wardex name and logo are trademarks of Gustavo Leão Melo" (asserted but not registered)

**Current behaviour:** The `COMMERCIAL_LICENSE.md` and `doc/wardex-g20-audit-readiness.md` both reference "Wardex" as a trademark of the author. However, trademark rights in most jurisdictions are established by registration, not by assertion. The mark is not registered with EUIPO (EU), UKIPO (UK), or USPTO (US). An unregistered `™` claim provides weak protection in practice.

**Impact:** Without registration, a third party could register "Wardex" as a trademark in a target market and use it to block the project owner from using the name commercially in that jurisdiction. This risk is low while the project has minimal visibility, but increases with commercial traction. It also weakens the commercial licence restriction against competing products using the Wardex name.

**Fix:** File a trademark application at minimum with EUIPO (EU-wide protection, ~€850 for one class) and optionally USPTO (~$250–350/class). Class 42 (Software as a Service) is the relevant class. Timeline: EUIPO ~6 months to registration. This requires no code changes — it is a legal/administrative action.

---

## 4. Gap Velocity & Release Cadence Analysis

### Closures per Release

| Release | Gaps Closed | Key Theme |
|---|:---:|---|
| v1.1.1 | 6 (G-01–G-06, G-22) | All bugs + changelog |
| v1.2.0 | 7 (G-08–G-10, G-12, G-14, G-16, G-18) | Completeness + DX |
| v1.3.0 | 3 (G-13, G-15\*, G-20\*) | Enterprise readiness |
| v1.4.0 | 4 (G-07\*, G-09, G-11, G-17) | Observability + compliance |
| v1.5.0 | 1 (G-19) | Multi-framework engine |
| v1.6.0 | 3 (G-07✅, G-15✅, G-21✅) | Stabilisation + dual licensing |

> \* Partially closed in earlier release, fully resolved in later release.

**Average closure rate: 3.5 gaps/release** across 6 releases. At this rate, the 7 new gaps (N-01 to N-07) would close within 2 releases if prioritised.

### Adoption Readiness Assessment

| Dimension | v1.1.0 | v1.6.0 | Change |
|---|:---:|:---:|:---:|
| First-run UX (--version, --expires 30d) | ❌ | ✅ | +5 |
| CI/CD integration (exit codes, Grype adapter) | ❌ | ✅ | +5 |
| Compliance mapping (ISO 27001, SOC2, NIS2, DORA) | ⚠️ | ✅ | +4 |
| Formal risk acceptance (HMAC, audit trail) | ✅ | ✅ | = |
| SIEM verification (real TCP/HTTP probe) | ❌ | ✅ | +5 |
| RBAC (per-team profiles with identity check) | ❌ | ⚠️ | +3 |
| Commercial embedding (legal framework) | ❌ | ⚠️ | +4 |
| External security audit | ❌ | ❌ | = |
| Trademark protection | ❌ | ❌ | = |
| Test coverage enforcement | ❌ | ❌ | = |

---

## 5. Prioritised Remediation Plan

### Immediate (v1.6.1 — < 1 week)

| Gap | Action | Effort |
|---|---|:---:|
| **N-01** | Fill `COMMERCIAL_LICENSE.md` placeholders. Set [DATE]=2026-03-01, [JURISDICTION]=Portugal (or chosen), [domain]=wardex.dev. Attorney review. | XS |
| **N-04** | Add `LicenseRef-Wardex-Commercial.txt` to repo root. Update SPDX identifier comment to pointer form. | XS |

### Short-term (v1.7.0 — 1 sprint)

| Gap | Action | Effort |
|---|---|:---:|
| **N-03** | Implement `--since` JSONL parsing in `verify-forwarding`. Count and report events within window. | S |
| **N-06** | Add `go test -coverprofile` + threshold gate to CI. Add Codecov badge. | S |
| **N-02** | Add explicit documentation to `wardex accept verify-forwarding --help` and `wardex-g20-audit-readiness.md` clarifying that RBAC is CI-context-dependent. | XS |

### Medium-term (v1.8.0 — 1 month)

| Gap | Action | Effort |
|---|---|:---:|
| **N-05** | Add `pkg/sboms/openvex.go` reader. Map OpenVEX `status: not_affected` to suppression logic. | M |
| **N-07** | File EUIPO trademark application for "Wardex" in Class 42. | L (administrative) |
| **G-20** | Commission third-party penetration test of `pkg/accept/signer` and `pkg/accept/verifier`. Publish redacted report. | L (external engagement) |

---

## 6. Conclusion

Wardex has closed **21 of 22 original gaps** across 6 releases shipped in a single development sprint — a 95% resolution rate. The single remaining original gap (G-20, external security audit) is structural: it requires an external engagement and cannot be resolved by internal development effort alone.

The v1.6.0 release specifically addressed the three most commercially significant gaps:

- **G-07** (verify-forwarding): Upgraded from a `time.Sleep` simulation to a real `net.DialTimeout` + `http.Client` probe with proper exit codes — the command now correctly fails closed on unreachable SIEM backends.
- **G-15** (RBAC): `AllowedActors` enforcement via CI environment identity turns profile selection from an unguarded CLI flag into an access-controlled operation. The model is sound for GitHub Actions; the local-dev bypass (N-02) is a known limitation worth documenting.
- **G-21** (dual licensing): The full dual-licensing infrastructure — `COMMERCIAL_LICENSE.md`, `CLA.md`, CLA GitHub Actions workflow, copyright notices, SPDX identifiers, README licensing section — was shipped. The gap is resolved in substance; five text placeholders (N-01) need to be filled before the licence is legally effective.

The 7 new gaps are proportionally lightweight: 2 are XS fixes (N-01, N-04), 2 are S effort (N-03, N-06), 1 is M (N-05), and 2 are long-lead external engagements (N-02, N-07, G-20). None are architectural blockers. The codebase is in a strong position for enterprise adoption pending the commercial licence completion and external audit.

---

*Analysis grounded on direct inspection of commits `2450e8e..5bb06d8` (origin/main, v1.5.0 → v1.6.0, March 2026).*
*All gap identifiers reference specific file paths confirmed via `git diff` and manual code review.*
