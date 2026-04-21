# Wardex — G-21 Execution Guide
## Dual-Licensing Strategy: AGPL-3.0 → AGPL-3.0 + Commercial

> **Legal disclaimer:** This document is a strategic and operational guide, not legal advice.
> Before publishing any commercial licence or accepting payment, engage a software IP attorney
> to review the final terms. Recommended specialisms: open-source licensing, SaaS contracts, IP assignment.
> Estimated legal review cost: $2,000–5,000 USD with a specialist firm.

---

## Why Dual Licensing Works for Wardex

Wardex is currently sole-authored (`had-nu`, single contributor, single copyright holder).
This is the **ideal starting position** for dual licensing — you own 100% of the copyright
and can grant any licence to any party without needing anyone else's permission.

The dual-licensing model works as follows:

```
┌─────────────────────────────────────────────────────────┐
│                   WARDEX SOURCE CODE                    │
│                   (one codebase)                        │
└────────────────────┬───────────────────┬────────────────┘
                     │                   │
          ┌──────────▼──────────┐  ┌─────▼──────────────────┐
          │   AGPL-3.0 (Free)   │  │  Commercial Licence     │
          │                     │  │  (Paid)                 │
          │ • OSS projects      │  │ • SaaS embedding        │
          │ • Internal use      │  │ • Proprietary products  │
          │ • Research          │  │ • White-label           │
          │ • Must open-source  │  │ • Source stays private  │
          │   network services  │  │ • Support SLA           │
          └─────────────────────┘  └────────────────────────┘
```

The commercial licence does not replace AGPL — it co-exists with it. Any user who
complies with AGPL (including open-sourcing their network service) pays nothing.
Any user who wants to embed Wardex in a proprietary SaaS without disclosing source
must purchase a commercial licence.

---

## Prerequisites: What Must Be True Before You Launch

### 1. Copyright Notice — Add Immediately

The current `LICENSE` file uses the FSF template without a copyright holder name.
You must add an explicit copyright notice at the top of `LICENSE` and across
all source files.

**Add to the top of `LICENSE`:**
```
Copyright (c) 2025–2026 Gustavo Leão Melo (had-nu)
All rights reserved, except as expressly granted under the licences below.
```

**Add to each `.go` file header (or create a `COPYRIGHT` file):**
```go
// Copyright (c) 2025–2026 Gustavo Leão Melo (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial
```

The `SPDX-License-Identifier` dual tag is the standard machine-readable signal
for dual-licensed software, recognised by GitHub, FOSSA, and most licence scanners.

### 2. Contributor Licence Agreement (CLA) — Before Accepting Any External PRs

**Current state:** Single contributor, no CLA needed for past commits.

**Future state:** The moment you accept a Pull Request from any external contributor,
that contributor's code is owned by them — not you. You cannot relicence their code
under a commercial licence without their explicit written permission.

**Action required:** Before merging any external PRs, implement a CLA:

- Use [CLA Assistant](https://cla-assistant.io/) (free, GitHub App) — contributors
  sign a CLA via a GitHub comment before their PR can be merged.
- The CLA should include: copyright assignment OR a broad licence grant to you
  to sublicence the contribution under any licence, including commercial.
- Template: `CLA.md` in the repository + CLA Assistant enforced in CI.

**Recommended CLA type for dual-licensing:** Copyright Assignment (not just licence grant).
Assignment means contributors transfer copyright to you. This gives you full
flexibility to relicence in the future. MongoDB, MySQL, and Elasticsearch all used
copyright assignment CLAs before their commercial pivots.

### 3. Decide on the Licence Grant Model

There are two common structures. Choose one before drafting the licence:

| Model | How it works | Best for |
|---|---|---|
| **Per-seat / per-developer** | Price scales with number of developers using Wardex in their build pipeline | Tooling embedded in CI/CD with known team sizes |
| **Per-deployment / per-service** | Price scales with the number of production services or pipelines gated by Wardex | SaaS platforms where "number of developers" is hard to define |
| **Revenue-based** | Small % of licensee's ARR — zero cost until revenue threshold | Startups; aligns incentives; harder to enforce |

**Recommendation for Wardex:** Per-seat (developers who trigger the gate in CI) with
a service cap for enterprise. This is the simplest to audit — GitHub Actions logs
show exactly which pipelines run Wardex.

---

## Execution Checklist — Step by Step

### Phase 1: Legal Groundwork (Week 1–2)

- [ ] Engage a software IP attorney. Brief them on: AGPL-3.0 base, single author, dual-licensing intent, planned commercial terms.
- [ ] Add copyright notice to `LICENSE` and all source files.
- [ ] Create `CLA.md` and configure CLA Assistant on the repository.
- [ ] Register the project name "Wardex" as a trademark in your target jurisdictions (at minimum: EU via EUIPO, ~€850; US via USPTO, ~$250–350). This protects the brand when issuing commercial licences.

### Phase 2: Licence Drafting (Week 2–3)

- [ ] Draft `COMMERCIAL_LICENSE.md` (template provided separately).
- [ ] Define the three commercial tiers (see Pricing section below).
- [ ] Attorney review of `COMMERCIAL_LICENSE.md` — budget $500–1,500 for this review.
- [ ] Define the Order Form template (separate from the licence terms).

### Phase 3: Infrastructure (Week 3–4)

- [ ] Set up a licence purchase flow. Options:
  - **Gumroad** (simplest — sell a PDF licence + invoice; Gumroad takes 10%)
  - **Paddle** (SaaS-oriented; handles EU VAT automatically; recommended for B2B SaaS)
  - **Stripe + custom portal** (most control; most setup effort)
- [ ] Create `wardex.dev` or similar domain for commercial enquiries.
- [ ] Set up `commercial@wardex.dev` or equivalent for licence requests.
- [ ] Create a `LICENCES.md` or update `README.md` with a clear dual-licence section.

### Phase 4: Launch (Week 4)

- [ ] Publish `COMMERCIAL_LICENSE.md` to the repository.
- [ ] Update `README.md` with the dual-licence notice and purchase link.
- [ ] Update `SPDX-License-Identifier` in all source files.
- [ ] Publish a blog post / GitHub Discussion explaining the licensing change and rationale.
- [ ] Notify any existing enterprise users (if any) that a commercial licence is now required for proprietary SaaS embedding.

---

## Pricing Model — Recommended Tiers

Based on comparable tools in the DevSecOps space (Semgrep, Snyk OSS → commercial,
Anchore Enterprise), the following tiers are recommended for Wardex v1.x:

### Tier 1 — Startup
- **Price:** $299 / month or $2,990 / year (17% discount)
- **Limits:** Up to 10 developers · Up to 5 production services
- **Includes:** Commercial embedding rights · Email support (48h SLA) · Minor version updates
- **Target:** Series A/B startups embedding Wardex in a proprietary product

### Tier 2 — Scale
- **Price:** $990 / month or $9,900 / year
- **Limits:** Up to 50 developers · Up to 50 production services
- **Includes:** All Startup features · Priority support (24h SLA) · Access to private roadmap
- **Target:** Growth-stage SaaS companies

### Tier 3 — Enterprise
- **Price:** Custom (starts at $25,000 / year for most enterprise engagements)
- **Limits:** Unlimited developers and services
- **Includes:** All Scale features · Dedicated Slack channel · Custom SLA · On-site/remote onboarding · Security audit report access · NDA available
- **Target:** Financial services, healthcare, regulated industries

### Internal Enterprise Use (Non-SaaS)
- **Price:** Free under AGPL-3.0
- **Condition:** AGPL allows internal use without disclosure requirements. A company
  can run Wardex in their own CI/CD pipeline without open-sourcing their internal
  infrastructure code, as long as they don't offer Wardex's functionality as a
  service to external users.
- **Note:** Clarify this explicitly in the README to avoid FUD — many enterprises
  mistakenly believe AGPL requires open-sourcing all internal code. It does not.

---

## The CLA: What to Include

The CLA (Contributor Licence Agreement) is the legal instrument that enables
dual licensing with external contributions. Key clauses:

```
1. GRANT OF COPYRIGHT LICENCE
   Contributor grants to the Project Owner a perpetual, worldwide, non-exclusive,
   no-charge, royalty-free, irrevocable copyright licence to reproduce, prepare
   derivative works of, publicly display, publicly perform, sublicense, and
   distribute Contributions and derivative works under any licence, including
   commercial licences.

2. GRANT OF PATENT LICENCE
   [Standard patent grant — required to prevent patent ambush]

3. REPRESENTATIONS
   Contributor represents that: (a) they have the legal right to make this
   Contribution; (b) the Contribution does not violate any third-party rights;
   (c) the Contribution is the Contributor's original creation.

4. NO OBLIGATION
   This CLA does not obligate the Project Owner to include the Contribution.
```

**Implementation:** [CLA Assistant](https://cla-assistant.io) is free and integrates
with GitHub. Configure it to block PR merges until the CLA is signed via a GitHub comment.

---

## How to Detect and Enforce the Commercial Licence

Enforcement of open-source licences against commercial violators is possible but
requires evidence. For Wardex, practical enforcement mechanisms include:

### Technical Signals
- Wardex CLI prints a version banner at startup. If a SaaS product's API response
  headers or error messages reveal Wardex version strings, this is evidence of embedding.
- The `wardex-accept-audit.log` format and `wardex-acceptances.yaml` schema are
  distinctive enough to be fingerprinted if discovered in a breach disclosure or
  public source leak.

### Legal Signals
- Job postings mentioning Wardex or wardex-style risk gating.
- GitHub repositories (public or leaked) containing Wardex in dependencies.
- Conference talks or blog posts disclosing Wardex usage without open-source compliance.

### Enforcement Path
1. Send a written notice to the company's legal team citing AGPL-3.0 Section 13.
2. Request either: (a) disclosure of source code per AGPL, or (b) purchase of a commercial licence.
3. If no response within 30 days, refer to an IP attorney for formal enforcement.

**Note:** AGPL enforcement is slow and expensive. The primary value of the commercial
licence is legitimate enterprises choosing to pay for simplicity and support, not
enforcement against bad actors. Price accordingly — enforcement cost should not
exceed expected licence revenue from any single enterprise.

---

## Comparable Precedents

| Project | Original Licence | Commercial Model | Outcome |
|---|---|---|---|
| Elasticsearch | Apache 2.0 | SSPL + Elastic Commercial | Controversial but successful; AWS forced to fork (OpenSearch) |
| GitLab | MIT (CE) | Commercial (EE) | CE/EE split works; strong community + revenue |
| Sidekiq | LGPL | Commercial (Pro/Enterprise) | Clean dual-licence; well-respected in Ruby community |
| Metabase | AGPL | Commercial (Enterprise) | AGPL for OSS, paid for embedding — closest to Wardex's model |
| Semgrep OSS | LGPL | Semgrep Pro/Team | Developer-led; OSS funnel → paid conversion |

**Closest analogy: Metabase.** Open-source analytics tool, AGPL-3.0, commercial
licence for proprietary embedding. They publish their [commercial terms publicly](https://www.metabase.com/license/commercial).
Reviewing their licence is recommended before finalising Wardex's terms.

---

## What to Avoid

- **Do not change the AGPL terms retroactively.** Users who relied on AGPL-3.0 have
  perpetual rights to the code they downloaded under that licence. You can only
  add new licences going forward.
- **Do not use a licence that is incompatible with AGPL for dependencies.**
  Wardex uses cobra (Apache 2.0) and yaml.v3 (MIT) — both compatible. Check any
  new dependency before adding it.
- **Do not rely on "asking nicely" for licence compliance.** The commercial licence
  must be legally enforceable. Have your attorney confirm that the governing law
  clause and dispute resolution mechanism are appropriate for your jurisdiction.
- **Do not price the commercial licence at a level that makes AGPL compliance
  more attractive.** If the commercial licence costs $50,000/year and AGPL compliance
  requires open-sourcing a $2,000/year internal tool, enterprises will choose AGPL
  compliance. Price to the value of the alternative (building equivalent functionality
  in-house), not the cost to you.

---

## Files to Create / Modify

| File | Action | Priority |
|---|---|---|
| `LICENSE` | Add copyright notice at top | Immediate |
| `COMMERCIAL_LICENSE.md` | Create (template in separate file) | Week 1 |
| `CLA.md` | Create (Contributor Licence Agreement) | Before next external PR |
| `CONTRIBUTING.md` | Add CLA requirement and link | With CLA.md |
| `README.md` | Add dual-licence notice and commercial link | Week 3 |
| All `*.go` files | Add SPDX dual identifier to file headers | Week 3 |
| `.github/workflows/cla.yml` | Add CLA Assistant workflow | With CLA.md |

---

*Strategy authored March 2026 based on Wardex v1.5.0 repository state.*
*Not legal advice. Engage a software IP attorney before publishing commercial licence terms.*
