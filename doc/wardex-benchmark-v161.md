# WARDEX — Competitive Benchmark Report
## Risk-Based Release Gate & Compliance Tooling — v2.0

**Wardex v1.6.1 vs Snyk · Trivy · Grype · Dependency-Track · Mend.io**

> March 2026 · Version 2.0 · Wardex v1.6.1 (AGPL-3.0 + Commercial dual-licence)
>
> Previous edition: v1.0 (March 2026, Wardex v1.1.0). This edition reflects 6 releases of
> Wardex development and updated data on all five competitor tools.

---

## 1. Executive Summary

This report benchmarks Wardex (v1.6.1) against five widely adopted security and compliance
tools — Snyk, Trivy, Grype, OWASP Dependency-Track, and Mend.io — across eleven dimensions.
Since the previous edition (Wardex v1.1.0), the competitive landscape has shifted on three axes
that directly affect Wardex's position: Grype has significantly upgraded its risk scoring engine;
Trivy has added VEX support; and the EU regulatory environment (DORA effective January 2025,
NIS2 enforcement active across member states) has made multi-framework compliance mapping a
first-class procurement criterion rather than a nice-to-have.

**Key findings (v2.0 vs v1.0):**

Wardex's moat on its core differentiators — risk-based release gating, compensating controls
modelling, and cryptographic risk acceptance — remains intact and uncontested. No evaluated tool
has moved to close any of these gaps. The meaningful changes since v1.0 are:

- **Wardex SCA/SBOM ingestion** improved from a pure consumer (score 1) to a capable multi-format
  processor (score 3): CycloneDX, SPDX, Grype JSON, and OpenVEX standalone documents are now
  all natively parsed. Wardex still does not generate SBOMs — that responsibility remains with
  Syft or Trivy in the recommended stack.

- **Multi-framework compliance** (SOC 2, NIS2, DORA, ISO 27001) is now a standalone scored
  dimension. Wardex is the only tool in this comparison with native mapping to all four frameworks.
  This directly addresses the regulated-sector adoption criteria that the v1.0 benchmark
  identified as a gap.

- **VEX** replaces "IaC & Secrets Scanning" as a benchmark dimension. Wardex now supports
  CycloneDX VEX (via `analysis.state`) and OpenVEX standalone documents. Grype and Trivy
  have also strengthened their VEX postures in 2025, making this a three-way competitive area.

- **Dual licensing** (AGPL-3.0 + Commercial) removes the previous licence-as-risk penalty in the
  TCO model for SaaS embedding use cases.

### Overall Scorecard — v2.0

Scale: 0 = N/A · 1 = Weak · 2 = Partial · 3 = Good · 4 = Strong · 5 = Category Leader

| Dimension | Wardex | Snyk | Trivy | Grype | Dep-Track | Mend.io | Δ Wardex |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Risk-Aware Release Gating | **5** | 1 | 1 | 2 | 2 | 1 | = |
| Composite Risk Scoring (CVSS+EPSS+Context) | **5** | 2 | 1 | 4 | 3 | 2 | = |
| Multi-Framework Compliance (ISO 27001·SOC 2·NIS2·DORA) | **5** | 2 | 0 | 0 | 1 | 2 | ↑ new |
| Compensating Controls Modelling | **5** | 0 | 0 | 0 | 0 | 0 | = |
| Formal Risk Acceptance (Auditable) | **5** | 2 | 0 | 0 | 1 | 1 | = |
| VEX Support | 4 | 1 | 4 | 4 | 3 | 1 | ↑ new |
| Vulnerability Scanning Breadth | 1 | **5** | **5** | 4 | 4 | **5** | = |
| SCA / SBOM Support | 3 | 4 | **5** | **5** | 4 | 4 | ↑ +2 |
| CI/CD Integration Depth | 4 | **5** | **5** | 4 | 3 | 4 | = |
| SDK / Embeddability | **5** | 3 | 2 | 3 | 3 | 2 | = |
| Economic Cost / TCO | **5** | 1 | 4 | **5** | 4 | 2 | = |

**Wardex Aggregate (sum):** 47/55 scored points (+3 from v1.0 on the comparable dimensions)
**Nearest overall competitor:** Grype at 28/55 (complementary, not substitutable)

---

## 2. Scope & Methodology

### 2.1 Tools Evaluated

| Tool | Version | Vendor | Primary Purpose | Licence / Pricing |
|---|---|---|---|---|
| **Wardex** | **v1.6.1** | had-nu | Risk-based release gate + multi-framework compliance mapper | AGPL-3.0 (free) + Commercial (from €2,990/yr) |
| Snyk | Enterprise | Snyk Ltd. | Developer security platform (SCA, SAST, Container, IaC) | Commercial — $1,260/dev/yr list |
| Trivy | v0.60+ | Aqua Security | Multi-layer vulnerability, misconfiguration & SBOM scanner | Apache 2.0 — Free |
| Grype | v0.96+ | Anchore | Vulnerability scanner with CVSS+EPSS+KEV+OpenVEX scoring | Apache 2.0 — Free |
| Dependency-Track | v4.12 | OWASP | SBOM-driven vulnerability & policy management platform | Apache 2.0 — Free |
| Mend.io | Enterprise | Mend (ex WhiteSource) | SCA, reachability analysis, licence compliance | Commercial — Enterprise custom |

### 2.2 What Changed Since v1.0

| Tool | Notable Changes Since v1.0 |
|---|---|
| Wardex | +5 features across 5 releases: multi-framework engine; Grype/CycloneDX/SPDX/OpenVEX ingestion; RBAC enforcement; dual licensing; real SIEM verification; CI coverage gate |
| Grype | DB v6 schema: EPSS+KEV+OpenVEX integrated natively. Risk column sorted by default. `grype db search` for direct DB querying |
| Trivy | VEX support added (CycloneDX BOM + CSAF format). "Next-Gen Trivy" announced for 2026 |
| Dependency-Track | v4.12 polished policy engine; BOM Processing V2 now default; improved CycloneDX VEX workflow |
| Snyk | AI-assisted remediation expanded; pricing unchanged at $1,260/dev/yr entry |
| Mend.io | No material public changes on the dimensions evaluated |

### 2.3 Scoring Criteria

Each tool scored 0–5 per dimension:

- **0** = Not available / N/A
- **1** = Weak or limited — core scenario not covered
- **2** = Partial — basic capability with material gaps
- **3** = Good — solid, production-usable, some limitations
- **4** = Strong — enterprise-grade, minor gaps
- **5** = Category leader — best-in-class for this dimension

Sources: official documentation, source code inspection, public benchmarks and peer reviews
(Q4 2025–Q1 2026), Wardex `test/poc` suite, and pricing data from Vendr.com and vendor sites.

---

## 3. Dimension-by-Dimension Analysis

### 3.1 Risk-Aware Release Gating

Measures whether a tool can block or allow a software release based on a contextualised,
multi-variable risk assessment — not a raw severity threshold.

| Tool | Score | Analysis |
|---|:---:|---|
| **Wardex** | **5** | Purpose-built release gate. Formula: `(CVSS × EPSS) × (1 − compEffect) × criticality × exposure`. ANY gate (single CVE breach) and AGGREGATE gate (sum of risk scores). Three decision bands: `ALLOW` (exit 0), `WARN` (exit 0, risk between `warn_above` and `risk_appetite`), `BLOCK` (exit 10). Cryptographic drift detection: gate refuses stale risk acceptances if `wardex-config.yaml` has changed since signing (exit 11). RBAC enforcement: `--profile` overrides require CI identity match against `AllowedActors`. |
| Snyk | 1 | Severity-based CI blocking (fail on CRITICAL). No contextual asset weighting, no compensating controls. Risk Score is advisory; the gate remains threshold-based. |
| Trivy | 1 | `--exit-code 1` with `--severity` filter. Purely threshold-based. No composite scoring, no asset context. |
| Grype | 2 | Risk column in tabular output (EPSS × CVSS/10 × impact, KEV boost). Best open-source scorer. Still a scanner — does not close the release gate. Output requires downstream scripting to make a CI pass/fail decision. |
| Dependency-Track | 2 | Policy engine can trigger webhooks on violations. Policies combine CVSS, EPSS, licence, and component age. No asset criticality weighting, no compensating controls. Async architecture makes inline CI gating cumbersome. |
| Mend.io | 1 | Builds block on severity + licence policy. No contextual risk formula, no formal risk acceptance. |

**Score movement:** No competitor has moved in this dimension since v1.0. Wardex's `RBAC enforcement` (v1.6.0) and `WARN band observability` (v1.2.0) increase the operational depth of the gate without changing the score, which was already at ceiling.

---

### 3.2 Composite Risk Scoring (CVSS + EPSS + Context)

Assesses the sophistication of the risk model: does the tool move beyond raw CVSS to incorporate
exploit probability, asset context, and defensive controls?

| Tool | Score | Analysis |
|---|:---:|---|
| **Wardex** | **5** | Five independent variables: CVSS base score, EPSS (exploit probability), asset criticality (0.0–1.0, configurable), exposure context (internet-facing, auth layer, environment tier), and compensating controls (capped at 0.80 combined effectiveness). Conservative defaults: EPSS=1.0 if absent, criticality=1.0 if zero. Risk appetite configurable per-pipeline and per-team via `--profile`. |
| Snyk | 2 | Proprietary Snyk Risk Score combines CVSS, EPSS, reachability (Java/JS/Python), social trends, and age. Reachability reduces noise. No compensating control input, no asset criticality weighting. Hard gate remains severity-threshold. |
| Trivy | 1 | Severity only (CVSS-derived: LOW/MEDIUM/HIGH/CRITICAL). No EPSS integration, no context weighting. |
| Grype | 4 | DB v6 (2025): `RiskScore = EPSS × (CVSS/10) × impact` scaled 0–100, with additive KEV boost and ransomware campaign boost. Default tabular output sorted by Risk. OpenVEX filtering now integrated. No asset criticality or compensating control inputs — scoring remains vulnerability-centric, not asset-centric. |
| Dependency-Track | 3 | Aggregates CVSS, EPSS (via FIRST API), NVD, OSS Index, GitHub Advisories. Policy engine can combine signals. No asset criticality, no compensating controls. Scoring is asynchronous. |
| Mend.io | 2 | CVSS with reachability (call-graph analysis). No EPSS, no asset criticality, no compensating controls. |

**Score movement:** Grype unchanged at 4 (DB v6 formalises the scoring, but the formula was already good in v1.0). The delta is that Grype's risk score is now surfaced by default in CLI output rather than requiring `--sort risk`.

---

### 3.3 Multi-Framework Compliance Mapping

**New dimension in v2.0.** Measures whether the tool natively maps security control data to
compliance frameworks and generates maturity/gap analysis as a CI/CD by-product.

| Tool | Score | Analysis |
|---|:---:|---|
| **Wardex** | **5** | Four frameworks natively supported as of v1.5.0–v1.6.0: **ISO 27001:2022 Annex A** (93 controls, 4 domains), **SOC 2 Trust Services Criteria**, **NIS2 Directive 2022/2555**, **DORA ICT risk management** (Regulation 2022/2554). Activated via `--framework iso27001|soc2|nis2|dora` flag. Catalog engine: `pkg/catalog/*.yaml` with abstract `CatalogControl` schema. High-confidence + inferential (regex-based) correlation for cross-standard mapping. Snapshot delta satisfies ISO 27001 Clause 10.2 and DORA Article 6 continuous improvement requirement. |
| Snyk | 2 | Reports available for PCI DSS, SOC 2 (partial), CIS benchmarks via IaC scanner. No formal Annex A mapping. No DORA or NIS2. Enterprise GRC integrations require custom API work. |
| Trivy | 0 | No compliance framework mapping of any kind. CIS Benchmarks for IaC are security configurations, not GRC control mapping. |
| Grype | 0 | Pure vulnerability scanner. No framework mapping. |
| Dependency-Track | 1 | No native framework mapping. Can serve as an evidence source for compliance programmes but the mapping is manual and external. Policy engine operates on vulnerability data, not control maturity. |
| Mend.io | 2 | PCI DSS and HIPAA compliance reports. No ISO 27001 Annex A, no DORA, no NIS2. Framework coverage is narrower than Snyk and not mapped to control maturity. |

**Market context:** DORA entered full application in January 2025 for EU financial services. The ESAs designated Critical ICT Third-Party Providers in November 2025. NIS2 transposition enforcement is active across all EU member states. This dimension has shifted from a differentiator to a procurement gate for regulated-sector clients — Wardex is the only evaluated tool that passes it without external tooling.

---

### 3.4 Compensating Controls Modelling

Can the tool accept descriptions of active defensive controls and mathematically reduce the
effective risk of a vulnerability based on their combined effectiveness?

| Tool | Score | Analysis |
|---|:---:|---|
| **Wardex** | **5** | Unique capability. Controls declared in `wardex-config.yaml` (`type` + `effectiveness 0.0–1.0`). Engine sums declared control effectiveness, clamps at 0.80, multiplies composite risk by `(1 − combinedEffect)`. Example: WAF(0.40) + MFA(0.30) + segmentation(0.15) = 0.85 → clamped to 0.80 → risk × 0.20. Quantitatively models defence-in-depth. |
| Snyk | 0 | No compensating control modelling. Not on public roadmap. |
| Trivy | 0 | No compensating control modelling. |
| Grype | 0 | CISA KEV boost reflects real-world exploitation context, but no defensive control input. |
| Dependency-Track | 0 | Binary component suppression only. No continuous effectiveness model. |
| Mend.io | 0 | No compensating control modelling. |

**Score movement:** None. This remains Wardex's most defensible moat — the feature requires an architectural commitment to modelling organisational security posture that no scanner-first tool has made.

---

### 3.5 Formal Risk Acceptance (Auditable)

Does the tool provide a structured, cryptographically verifiable mechanism for risk exception
management, as required by ISO 27001 Clause 6.1.3 and Clause 8.3, DORA Article 8?

| Tool | Score | Analysis |
|---|:---:|---|
| **Wardex** | **5** | Full exception lifecycle: `wardex accept request` → HMAC-SHA256 signed record (payload: CVE, owner, justification, expiry, config-hash) → append-only JSONL audit log → SIEM forwarding (Syslog, Webhook, AWS CloudWatch, GCP Logging, all via build tags). Tamper detection: `wardex accept verify` → exit 11 on any alteration. Config drift detection: if `wardex-config.yaml` changes after signing, the acceptance is invalidated. TTL enforcement: expired exceptions silently rejected. RBAC enforcement: `AllowedActors` per profile. Documented for auditors in `doc/wardex-g20-audit-readiness.md` with SOC 2 (CC7.1), ISO 27001 (A.8), and DORA alignment. |
| Snyk | 2 | Vulnerability suppression with reason and expiry. No cryptographic signing, no tamper detection, no SIEM forwarding. Suppressions editable in dashboard without immutable audit trail. Adequate for operational suppression; insufficient for GRC formal risk acceptance. |
| Trivy | 0 | No formal risk acceptance. `.trivyignore` file is a static ignore list with no audit trail. |
| Grype | 0 | No formal risk acceptance. VEX documents can serve an adjacent pattern but are external to Grype. |
| Dependency-Track | 1 | Component-level suppression with analyst notes and justification text. No cryptographic integrity, no TTL-based auto-revocation, no SIEM forwarding. Policy engine improved in v4.12 but still no immutable audit chain. |
| Mend.io | 1 | Manual vulnerability suppression with notes. No cryptographic trail, no GRC-grade audit log. |

---

### 3.6 VEX Support

**New dimension in v2.0.** Measures support for the Vulnerability Exploitability eXchange
standard — the ability to ingest, process, and act on statements that a reported vulnerability
does not affect a specific product in a specific deployment context.

| Tool | Score | Analysis |
|---|:---:|---|
| **Wardex** | 4 | Two VEX ingestion paths: (a) CycloneDX SBOM with embedded `analysis.state` — `false_positive` or `not_affected` → `Reachable=false` (v1.4.0); (b) standalone OpenVEX JSON-LD documents at `https://openvex.dev/ns/v0.2.0` — `not_affected`/`false_positive` → suppression, `affected`/`under_investigation` → Reachable=true (v1.6.1). Auto-detection in `cmd/convert/sbom.go` via `peekSbomFormat()`. Gap: CSAF VEX format not yet supported; no dynamic VEX retrieval from SBOM external references. |
| Snyk | 1 | No standards-based VEX ingestion. Suppression workflows are proprietary. No CycloneDX VEX, no OpenVEX, no CSAF. |
| Trivy | 4 | CycloneDX Independent BOM/VEX BOM format supported (`--vex` flag alongside SBOM scan). CSAF 2.0 VEX supported (SBOM format-agnostic). Gap: OpenVEX standalone not natively supported; dynamic VEX retrieval from SBOM external references under discussion (open GitHub issue). |
| Grype | 4 | OpenVEX support for filtering and augmenting scan results, documented in README as a primary feature (v0.88+). DB v6 processes OpenVEX via `processors/openvex` in the database build pipeline. Gap: no CycloneDX BOM-embedded VEX parsing; CSAF not supported. |
| Dependency-Track | 3 | CycloneDX VEX workflow: analyses applied from VEX documents to components in portfolio. Integrates with VEX statements via CycloneDX format. V4.12 logs warnings when VEX analyses could not be applied. Gap: OpenVEX standalone not supported; no CSAF. |
| Mend.io | 1 | No standards-based VEX. Proprietary suppression only. |

**Coverage matrix for reference:**

| VEX Format | Wardex | Trivy | Grype | Dep-Track |
|---|:---:|:---:|:---:|:---:|
| CycloneDX BOM-embedded VEX | ✅ | ✅ | — | ✅ |
| OpenVEX standalone (JSON-LD) | ✅ | — | ✅ | — |
| CSAF 2.0 VEX | — | ✅ | — | — |

---

### 3.7 Vulnerability Scanning Breadth

Does the tool produce its own vulnerability findings, and how comprehensive is the coverage?

| Tool | Score | Analysis |
|---|:---:|---|
| Wardex | 1 | Not a scanner — by design. Ingests output from scanners (Grype YAML, CycloneDX SBOMs, SPDX, OpenVEX) and applies its risk model. Recommended pairing: Grype or Trivy (scan) → Wardex (gate). |
| **Snyk** | **5** | Broadest proprietary database. SCA across 50+ languages, container images, IaC, SAST. CVEs typically reported ~47 days ahead of NVD. AI-assisted remediation PRs. 1,200+ enterprise customers. |
| **Trivy** | **5** | Single binary, zero dependencies. OS packages (Alpine, Debian, RHEL, Ubuntu, etc.), 30+ language ecosystems, IaC misconfigurations, secrets, Kubernetes cluster scanning, SBOM generation (CycloneDX + SPDX). "Next-Gen Trivy" announced for 2026. |
| Grype | 4 | NVD, GitHub Advisories, Alpine SecDB, RHSA, Debian DSA, Ubuntu USN, OSV, and more. No IaC, no secrets, no SAST. DB v6 schema significantly faster and more accurate than v5. Pairs with Syft for SBOM-first workflows. |
| Dependency-Track | 4 | Multi-source aggregation: NVD, GitHub Advisories, Sonatype OSS Index, Snyk, Trivy, OSV, VulnDB. Portfolio-level monitoring. Async analysis. |
| **Mend.io** | **5** | Deep SCA with call-graph reachability analysis. Licence compliance. Real-time new CVE monitoring. |

---

### 3.8 SCA / SBOM Support

Ability to generate, ingest, enrich, and act on Software Bills of Materials.

| Tool | Score | Analysis |
|---|:---:|---|
| **Wardex** | **3** | Ingestion-only, no generation. Natively parses: CycloneDX 1.5 JSON (`pkg/sboms/cyclonedx.go`), SPDX JSON (`pkg/sboms/spdx.go`), Grype JSON output (`cmd/convert/grype.go`), OpenVEX JSON-LD (`pkg/sboms/openvex.go`). Auto-format detection in `cmd/convert/sbom.go`. SBOM generation responsibility remains with Syft or Trivy. Score reflects v1.0→v1.6.1 upgrade from 1 to 3. |
| Snyk | 4 | SBOM import and export (CycloneDX, SPDX). SCA powered by own dependency graph. Reachability analysis for Java, JS, Python. No SBOM generation as a primary workflow (scanner-centric). |
| **Trivy** | **5** | Best-in-class SBOM toolchain. Generates CycloneDX and SPDX from container images, filesystems, and repos. Scans SBOMs directly. Integrates with Syft-generated SBOMs. VEX alongside SBOM scanning. |
| **Grype** | **5** | SBOM-first design: `grype sbom:./sbom.json`. Pairs with Syft for generation. Best open-source SCA+SBOM pipeline. DB v6 with EPSS+KEV embedded per CVE. OpenVEX filtering on SBOM scan results. |
| Dependency-Track | 4 | Purpose-built SBOM management platform. Multi-project portfolio. CycloneDX-native. BOM Processing V2 (default in v4.12) significantly faster. |
| Mend.io | 4 | SBOM import/export. Deep SCA with dependency tree. Licence compliance layer. |

---

### 3.9 CI/CD Integration Depth

How natively and frictionlessly does the tool integrate into automated pipelines?

| Tool | Score | Analysis |
|---|:---:|---|
| Wardex | 4 | CLI-first, single binary, composable exit codes (0/10/11). GitHub Actions, GitLab CI, and Jenkins integration via shell steps. SIEM verification command (`wardex accept verify-forwarding`) with real TCP/HTTP probe and `--since` JSONL filtering. Grype output as native input format eliminates converter boilerplate. Gap: no official GitHub Actions marketplace action yet; no native IDE plugin. |
| **Snyk** | **5** | Official GitHub Actions, GitLab, Jenkins, Azure DevOps plugins. IDE plugins (VS Code, IntelliJ). PR checks with automated fix suggestions. Best-in-class developer feedback loop. |
| **Trivy** | **5** | Official GitHub Actions, GitLab, Jenkins, Azure DevOps integrations. Kubernetes Operator (`trivy-operator`) for in-cluster scanning. Supports SARIF output for GitHub Code Scanning. Aqua Platform for dashboards. |
| Grype | 4 | CLI + GitHub Actions integration. Grype Action in marketplace. SARIF output. Clean exit code model. |
| Dependency-Track | 3 | Jenkins plugin (synchronous mode: upload SBOM and wait for result). GitHub Actions via API. Server-based architecture adds latency to CI loops. |
| Mend.io | 4 | GitHub, GitLab, Azure DevOps, Jenkins, Bitbucket integrations. Automated PR remediation. |

---

### 3.10 SDK / Embeddability

Can the tool's core engine be imported as a library into a custom Go (or other language) service?

| Tool | Score | Analysis |
|---|:---:|---|
| **Wardex** | **5** | All core logic in `pkg/` — independently importable Go packages: `pkg/releasegate`, `pkg/scorer`, `pkg/analyzer`, `pkg/correlator`, `pkg/ingestion`, `pkg/accept`, `pkg/report`, `pkg/sboms`, `pkg/catalog`. No external service dependencies at runtime. Full GoDoc annotations (v1.2.0+). Dual licence enables proprietary embedding (Commercial tier from €2,990/yr). SPDX identifier on all source files. |
| Snyk | 3 | REST API available. SDKs for major languages. Not embeddable as a library; requires API calls to Snyk's SaaS. |
| Trivy | 2 | Go library (`github.com/aquasecurity/trivy/pkg`) technically importable but large, complex, and not designed for direct library embedding. Scanner-first design. |
| Grype | 3 | Go library (`github.com/anchore/grype`) usable as a dependency. Better than Trivy for embedding. Still scanner-centric design. |
| Dependency-Track | 3 | REST API. Java-based; not directly embeddable as a library in other language stacks. |
| Mend.io | 2 | SaaS API only. No embeddable library. |

---

### 3.11 Economic Analysis (TCO)

**Reference organisation:** 50 developers · 200 microservices · ISO 27001 target ·
DORA compliance required (financial services) · GitHub Actions CI/CD.

#### Pricing (Annual, 50-developer team)

| Tool | Model | Annual Cost (50 devs) | Source |
|---|---|:---:|---|
| Wardex (internal use) | AGPL-3.0 free | **€0** | Internal CI/CD use requires no licence |
| Wardex (SaaS embedding) | Commercial Scale | **€9,900/yr** | Schedule A, Tier 2 |
| Snyk Enterprise | Per contributing dev | **~€32–44K/yr** | $34,886 median / $47,413 p95 at 50 devs (Vendr, 2025); 34% typical discount from $1,260/dev/yr list |
| Trivy | Apache 2.0 | **€0** | Self-hosted |
| Grype | Apache 2.0 | **€0** | Self-hosted |
| Dependency-Track | Apache 2.0 | **€0** | Self-hosted; infrastructure cost only |
| Mend.io | Enterprise custom | **~€35–70K/yr** | No public pricing; estimates from procurement data |

#### 3-Year TCO Model (50-dev team, ISO 27001 + DORA goal)

Cost components: licence, self-hosted infrastructure (AWS t3.medium equivalent),
initial integration (one-time, €130/hr blended), ongoing maintenance (5 hr/month),
gap-fill tooling costs (tools needed to meet the DORA+ISO 27001 target not covered by the primary tool).

| Cost Component (3 yr) | Wardex | Snyk | Trivy | Grype | Dep-Track | Mend.io |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Software Licence | €0 | €96–132K | €0 | €0 | €0 | €105–210K |
| Infrastructure (self-hosted) | €1.6K | €0 (SaaS) | €1.6K | €1.6K | €3.2K | €0 (SaaS) |
| Setup / Integration | €5.2K | €4K | €4K | €4K | €8K | €5.2K |
| Ongoing Maintenance (3 yr) | €7K | €4.7K | €4.7K | €4.7K | €9.4K | €4.7K |
| Gap-fill tooling* | €1.6K | €2.6K | €9K | €5.2K | €2.6K | €2.6K |
| Multi-framework compliance tool† | €0 | €7.8K | €7.8K | €7.8K | €7.8K | €4K |
| **TOTAL (3-yr estimate)** | **€15.4K** | **€115–150K** | **€27.1K** | **€23.3K** | **€31K** | **€121–226K** |

> \* Gap-fill: Wardex needs a scanner (Grype, free). Trivy/Grype need a gate + compliance tool.
>   Dep-Track needs a gate engine.
>
> † ISO 27001 + DORA control mapping tool required for regulated organisations. Only Wardex
>   covers this natively. Estimate for external tool or GRC consultant engagement: €7.8K over 3 yr.

#### Wardex 3-Year TCO vs Alternatives (Internal Use, ISO 27001 + DORA target)

```
Wardex         ████  €15.4K
Grype+gate     ███████  €23.3K
Trivy+gate     █████████  €27.1K
Dep-Track      ███████████  €31K
Snyk           ████████████████████████████████████████  €115–150K
Mend.io        ████████████████████████████████████████████████████████████  €121–226K
```

Wardex's 3-year TCO is **7.5–9.7× lower than Snyk** and **7.9–14.7× lower than Mend.io** for
a 50-developer team in a regulated sector.

#### ROI Drivers

| Driver | Estimated Annual Value (50-dev team) |
|---|---|
| False-positive reduction | Teams using context-aware scoring report 60–80% fewer actionable false positives vs CVSS-threshold gates. At 20 min/alert × 5 alerts/wk × €60/hr blended = ~€52K/yr recovered |
| ISO 27001 audit preparation | Wardex generates Annex A gap analysis as a CI by-product. Replaces €10–25K/yr consulting engagement |
| DORA compliance evidence | Automated release gate decisions as ICT risk management evidence (DORA Article 8). Reduces audit prep by estimated 40 hrs/yr at €130/hr = €5.2K/yr |
| Avoided breach cost | IBM Cost of Data Breach 2024: $4.88M global average. Even 1% improvement in risk-gating effectiveness on a weekly release pipeline = ~€24K/yr expected-value |
| Developer pipeline fatigue | Context-aware blocking reduces override incidents from ~weekly to near-zero. Conservative estimate: 2 hr/incident × 26 incidents/yr × €80/hr (DevOps) = €4.2K/yr |

---

## 4. Strategic Positioning Matrix (Updated)

Tools mapped on two axes:
- **X-axis** — Scanning Breadth: surface areas covered (OS, SCA, IaC, SAST, container)
- **Y-axis** — Decision Sophistication: how context-aware, asset-weighted, and audit-grade the gate/decision engine is

```
Decision         │ Low Scanning Breadth     │  High Scanning Breadth
Sophistication   │                          │
─────────────────┼──────────────────────────┼───────────────────────────────
        ▲ HIGH   │  ★ WARDEX v1.6.1         │  ◎ MARKET OPPORTUNITY
                 │  Risk gate + 4 frameworks │  "Wardex breadth" — a tool
                 │  + compensating controls  │  combining Snyk/Trivy scanning
                 │  + OpenVEX + DORA/NIS2   │  with Wardex-level decisions
─────────────────┼──────────────────────────┼───────────────────────────────
        ▼ LOW    │  (minimal scanners)      │  SNYK · TRIVY · GRYPE
                 │                          │  DEP-TRACK · MEND
                 │                          │  (broad scanning, threshold gates)
```

**The "Market Opportunity" quadrant remains vacant.** No commercial or open-source tool has
combined Snyk/Trivy scanning breadth with Wardex-level risk-decision depth. Wardex's own roadmap
(no native scanner by design) keeps it in the High-Decision / Low-Scanning quadrant — the
recommended counter is to pair Wardex with Grype or Trivy to cover both axes at zero incremental cost.

---

## 5. Ideal Use Case Mapping (Updated)

★★★ = Best choice · ★★ = Good fit · ★ = Possible with integration · — = Not applicable

| Use Case | Wardex | Snyk | Trivy | Grype | D-Track | Mend |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Replace CVSS gate with risk-aware CI/CD gating | **★★★** | ★ | ★ | ★★ | ★★ | ★ |
| ISO 27001 certification evidence & maturity scoring | **★★★** | — | — | — | ★ | ★ |
| SOC 2 Type II / NIS2 / DORA compliance mapping | **★★★** | ★ | — | — | — | ★ |
| Formal, auditable risk acceptance (GRC/audit) | **★★★** | ★ | — | — | ★ | ★ |
| Compensating controls quantitative modelling | **★★★** | — | — | — | — | — |
| VEX-based vulnerability suppression | **★★** | — | **★★★** | **★★★** | ★★ | — |
| Container / OS vulnerability scanning | ★ | **★★★** | **★★★** | **★★★** | ★★ | **★★★** |
| IaC misconfiguration detection | — | **★★★** | **★★★** | — | — | ★★ |
| SBOM generation & lifecycle management | ★ | ★★ | **★★★** | **★★★** | **★★★** | ★★ |
| Air-gapped / offline deployments | **★★★** | ★ | **★★★** | **★★★** | ★★ | ★ |
| Embedding risk engine in a Go SaaS product | **★★★** | ★ | ★ | ★★ | ★ | — |
| Budget-constrained team (zero licensing cost) | **★★★** | ★ | **★★★** | **★★★** | **★★★** | ★ |

---

## 6. Wardex Robustness Assessment (Updated)

| Indicator | v1.0 | v1.6.1 | Evidence |
|---|:---:|:---:|---|
| Cryptographic integrity | 5/5 | 5/5 | HMAC-SHA256 on every risk acceptance. No secret in code. Exit 11 on tamper. Config drift detection. |
| Input validation & fuzzing | 5/5 | 5/5 | Native Go fuzzing in `pkg/ingestion`. Zero panics. Schema validation enforced pre-parse. |
| Fail-closed design | 5/5 | 5/5 | Exit 10 on BLOCK, 11 on tamper/drift. Gate refuses ALLOW on expired or stale acceptances. |
| Stateless / no external deps | 5/5 | 5/5 | Single binary. No database, no runtime service. Two direct deps (cobra, yaml.v3). |
| Audit immutability | 5/5 | 5/5 | Append-only JSONL audit log. UTC timestamps. SIEM forwarding multiplexer (Syslog, Webhook, CloudWatch, GCP). |
| Test coverage (CI enforced) | 4/5 | 4/5 | 70% threshold enforced in CI (`go test -coverprofile`, `bc -l` gate). Public coverage badge added. |
| Conservative risk defaults | 5/5 | 5/5 | EPSS=1.0 if absent. Criticality=1.0 if zero. CompEffect capped at 0.80. No optimistic bias. |
| SDK separation of concerns | 5/5 | 5/5 | `pkg/` cleanly separated. All packages independently importable. GoDoc complete. |
| Multi-format SBOM support | 1/5 | 3/5 | CycloneDX, SPDX, Grype JSON, OpenVEX all parsed natively. SBOM generation not in scope. |
| RBAC / access control | 1/5 | 3/5 | `AllowedActors` per profile. CI identity enforcement (GITHUB_ACTOR/WARDEX_ACTOR). Local-dev limitation documented. |
| Community maturity | 1/5 | 2/5 | 6 releases shipped. Dual-licence commercial offering. CLA workflow live. No external CVEs against Wardex. |
| Documentation quality | 3/5 | 4/5 | GoDoc complete. 4-language READMEs. Audit architecture doc (`wardex-g20-audit-readiness.md`). CHANGELOG maintained. |
| Licence | 3/5 | 4/5 | Dual licence: AGPL-3.0 (internal use free) + Commercial (SaaS embedding, from €2,990/yr). CLA workflow enforced on external contributions. |

---

## 7. Recommended Integration Stack (2026 Edition)

### Zero-licensing-cost, ISO 27001 + DORA-aligned CI/CD

| Layer | Tool | Role | Cost |
|---|---|---|---|
| SBOM Generation | Syft (Anchore) | Generate CycloneDX/SPDX SBOM from container image or filesystem | Free |
| Vulnerability Scanning | Grype (Anchore) | Scan SBOM against NVD, GitHub Advisories, KEV, EPSS; export YAML | Free |
| IaC Scanning | Trivy | Scan Terraform, Kubernetes, Helm for misconfigurations | Free |
| VEX Management | OpenVEX (CISA tooling) | Author and maintain standalone VEX documents | Free |
| **Risk Gate & Compliance** | **Wardex** | Ingest Grype/SBOM/VEX; apply composite risk formula; gate release; map ISO 27001, SOC 2, NIS2, DORA | Free (AGPL-3.0 internal) |
| Portfolio Dashboard | Dependency-Track | Portfolio-level SBOM tracking and trend monitoring | Free |
| GRC Evidence Store | Wardex reports (JSON/Markdown) | ISO 27001 Annex A gap reports as audit evidence (Clauses 9.1, 10.2) + DORA ICT risk management records | Free |

**Total licensing cost: €0.** Infrastructure cost: ~€50–100/month for self-hosted toolchain.

### For SaaS Embedding (Commercial Use)

Replace the "Free (AGPL-3.0 internal)" line with Wardex Commercial Tier 1 (€2,990/yr) or
Tier 2 (€9,900/yr) depending on developer count and service volume.

---

## 8. Open Gaps in Wardex (Updated from v1.0)

| Gap | Severity | Status vs v1.0 | Recommendation |
|---|:---:|:---:|---|
| No native vulnerability scanner | Medium | Unchanged (by design) | Document canonical stack: Syft → Grype → Wardex. Provide reference GitHub Actions workflow in `doc/` |
| External security audit absent | High | Unchanged | Commission CREST/OSCP pentest of `pkg/accept/signer` + `pkg/accept/verifier`. Required for regulated-sector enterprise procurement |
| RBAC validity limited to CI context | Low | **Improved** — limitation documented in `wardex-g20-audit-readiness.md` | Document `WARDEX_ACTOR` as the override mechanism and its limitations; consider OIDC token validation for high-assurance environments |
| No trademark registration | Low | Unchanged | File EUIPO application, Class 42. ~€850 |
| CSAF VEX format not supported | Low | New gap | Add `pkg/sboms/csaf.go` parser. CSAF 2.0 is SBOM-format-agnostic and growing in adoption, especially in EU (BSI mandates CSAF for German software supply chain) |
| No GitHub Actions marketplace action | Low | New gap | Publish `wardex-gate` GHA action. Reduces adoption friction from multi-line shell script to 3-line YAML step |
| Community immaturity | Medium | **Improving** | 6 releases, dual-licence, CLA live. Mitigation: pin to semver tag, maintain internal fork for critical pipelines |

---

## 9. Conclusions

Wardex v1.6.1 has substantially closed the gaps identified in the v1.0 benchmark while its
competitors have not moved on the dimensions where Wardex holds a structural advantage.

The five core differentiators — **risk-based release gating, compensating controls modelling,
formal auditable risk acceptance, multi-framework compliance mapping, and embeddable Go SDK** —
remain uncontested. No evaluated commercial or open-source tool replicates any of these, let
alone all five together.

The three meaningful competitive developments since v1.0 are:

**Grype** has formalised and surfaced its EPSS+KEV risk scoring in DB v6, making it a stronger
scanner complement (and making the Wardex ← Grype integration more valuable, since Wardex now
natively ingests Grype output).

**Trivy** has added CSAF and CycloneDX VEX support, which Wardex does not yet cover for CSAF.
The gap is narrow — Wardex covers OpenVEX and CycloneDX; Trivy covers CycloneDX and CSAF — but
CSAF adoption is growing in the EU, making this worth tracking.

**The EU regulatory environment** has validated Wardex's multi-framework roadmap. DORA entered
full force in January 2025; NIS2 is in active enforcement. The decision to build native SOC 2,
NIS2, and DORA catalog engines (v1.5.0, March 2026) was well-timed. Wardex is now the only
evaluated tool that a DORA-regulated financial institution can point to for automated,
CI/CD-integrated ICT risk management evidence.

For organisations targeting ISO 27001:2022 certification and/or DORA compliance who run
Go-based or polyglot CI/CD pipelines, **the Syft + Grype + Wardex stack delivers zero-licensing-cost
functionality that exceeds Snyk Enterprise on the dimensions most material to secure release
governance and regulatory compliance — at 7–15× lower 3-year TCO.**

---

*Report version 2.0 — Wardex v1.6.1 — March 2026*
*Predecessor: Benchmark Report v1.0 (Wardex v1.1.0, March 2026)*
*Sources: Wardex source code (github.com/had-nu/wardex); Snyk.io/plans; Vendr.com/marketplace/snyk;
Anchore.com/blog; pkg.go.dev/github.com/anchore/grype; trivy.dev/docs; docs.dependencytrack.org;
digital-operational-resilience-act.com; FIRST.org/epss; CISA KEV catalog.*
