# Wardex EPSS Enrichment — Multi-Context Stress Test Report

**Date:** 2026-03-06  
**Version:** v1.7.0  
**Author:** André Ataíde (Hadnu)  
**Tool:** Wardex Risk-Based Release Gate + FIRST.org EPSS API  

---

## 1. Objective

Validate the Wardex EPSS Enrichment pipeline (`wardex enrich epss`) and the contextual Risk Gate Engine (`scorer.go`) under production-realistic conditions:

- **237 real CVEs** from NVD (2014–2024), spanning 15+ technology ecosystems
- **Live EPSS scores** fetched from `api.first.org/data/v1/epss`
- **4 organizational risk profiles** with distinct appetites, asset contexts, and compensating controls

The goal is to prove that:
1. Without EPSS data, the gate **blocks 100%** of vulnerabilities (fail-close)
2. With real EPSS data, the gate **produces diverse, context-aware decisions**
3. The **same CVE** yields different risk scores depending on organizational context

---

## 2. Test Data

### 2.1 Vulnerability Corpus

237 historically significant CVEs including:

| Ecosystem | Examples | Count |
|---|---|---|
| Linux Kernel | Dirty COW, Dirty Pipe, PwnKit | 12 |
| Apache | Log4Shell, Struts2, ActiveMQ | 10 |
| OpenSSL / TLS | Heartbleed, CVE-2022-3602 | 8 |
| Node.js / NPM | minimist, lodash, protobufjs | 17 |
| Python / PyPI | requests, urllib3, setuptools | 8 |
| Go / Golang | net/http, protobuf, stdlib | 9 |
| Java / Maven | Spring4Shell, Commons Text, Jenkins | 12 |
| Chrome / Chromium | V8 RCE, libwebp, libvpx | 13 |
| Windows / Microsoft | EternalBlue, Zerologon, ProxyLogon | 10 |
| Docker / Kubernetes | runc, containerd, CRI-O | 8 |
| Networking / Firewall | FortiOS, PAN-OS, Citrix, Cisco | 12 |
| CI/CD / DevOps | GitLab, TeamCity, Jenkins | 4 |
| Databases | Redis, PostgreSQL, MySQL | 8 |
| C System Libraries | glibc, zlib, libexpat, GnuTLS | 12 |
| Other | WordPress, PHP, SolarWinds, Atlassian | 54+ |

All CVEs entered the pipeline with `epss_score: 0.0` (unknown), forcing the gate to assume worst-case (1.0) until enriched.

### 2.2 Organizational Profiles

| Profile | Appetite | Internet | Auth | Criticality | Compensating Controls |
|---|---|---|---|---|---|
| [BANK] **Banco Tier-1** (DORA) | 0.5 | [YES] Public API | [NO] Pre-auth | 1.5x | None |
| [HOSP] **Hospital** (HIPAA) | 0.8 | [YES] Patient portal | [YES] Required | 1.3x | IDS/IPS (20%) |
| [SAAS] **Startup SaaS** | 2.0 | [NO] Internal | [YES] Service auth | 0.8x | WAF + Rate Limiting (30%) |
| [DEV] **Dev Sandbox** | 4.0 | [NO] Isolated | [NO] None | 0.3x | Network Isolation (40%) + Ephemeral containers (30%) |

---

## 3. Results

### 3.1 EPSS Enrichment Performance

| Metric | Value |
|---|---|
| CVEs submitted | 237 |
| CVEs returned by FIRST.org | 237 (100%) |
| HTTP batches | 5 (50 CVEs/batch) |
| Inter-batch delay | 500ms (polite) |
| Total API time | **4.726 seconds** |
| HMAC-SHA256 signing | < 1ms |

### 3.2 Gate Without Enrichment (Baseline)

```
[HINT] 237 vulnerabilities lacked EPSS scores and defaulted to worst-case (1.0).
Release Gate Decision: [X] BLOCK
```

**237 / 237 BLOCKED (100%)** — Fail-close semantics confirmed.

### 3.3 Gate With Real EPSS — Distribution by Profile

| Profile | BLOCK | ALLOW | % Block |
|---|---|---|---|
| [BANK] Banco Tier-1 | **176** | 57 | **74%** |
| [HOSP] Hospital | **168** | 63 | **71%** |
| [SAAS] Startup SaaS | **111** | 86 | **47%** |
| [DEV] Dev Sandbox | **0** | 238 | **0%** |

### 3.4 Contextual Decision Divergence — Same CVE, 4 Decisions

The Risk Gate formula:

```
FinalRisk = (CVSS × EPSS) × (1 − CompensatingEffects) × Criticality × ExposureFactor
```

| CVE | CVSS | EPSS | [BANK] | [SAAS] | [DEV] | [HOSP] |
|---|---|---|---|---|---|---|
| **CVE-2021-44228** (Log4Shell) | 10.0 | 0.94 | **14.2** `BLOCK` | **2.5** `BLOCK` | **0.3** `ALLOW` | **7.9** `BLOCK` |
| **CVE-2024-3094** (xz backdoor) | 10.0 | 0.86 | **12.8** `BLOCK` | **2.3** `BLOCK` | **0.2** `ALLOW` | **7.1** `BLOCK` |
| **CVE-2023-38545** (curl SOCKS5) | 9.8 | 0.26 | **3.9** `BLOCK` | **0.7** `ALLOW` | **0.1** `ALLOW` | **2.1** `BLOCK` |
| **CVE-2023-45288** (Go HTTP/2) | 9.8 | 0.71 | **10.5** `BLOCK` | **1.9** `WARN` | **0.2** `ALLOW` | **5.8** `BLOCK` |
| **CVE-2021-44906** (minimist) | 9.8 | 0.01 | **0.1** `ALLOW` | **0.0** `ALLOW` | **0.0** `ALLOW` | **0.1** `ALLOW` |
| **CVE-2020-15257** (containerd) | 5.2 | 0.12 | **0.9** `BLOCK` | **0.2** `ALLOW` | **0.0** `ALLOW` | **0.5** `WARN` |

### 3.5 Risk Arithmetic — Log4Shell Deep Dive

**Base:** CVSS 10.0 × EPSS 0.94 = **9.4** adjusted score.

| Factor | [BANK] | [SAAS] | [DEV] | [HOSP] |
|---|---|---|---|---|
| Exposure (internet x auth x reachable) | 1.0 | 0.48 | 0.3 | 0.8 |
| Compensating (1 - effect) | 1.0 | 0.7 | 0.3 | 0.8 |
| Criticality | 1.5 | 0.8 | 0.3 | 1.3 |
| **Final Risk** | **14.2** | **2.5** | **0.3** | **7.9** |
| **vs Appetite** | 14.2 > 0.5 `BLOCK` | 2.5 > 2.0 `BLOCK` | 0.3 < 4.0 `ALLOW` | 7.9 > 0.8 `BLOCK` |

---

## 4. Key Findings

### 4.1 CVSS ≠ Risk

The CVE `CVE-2021-44906` (minimist prototype pollution) carries a CVSS of **9.8 (CRITICAL)** but an EPSS of **0.01** (1% real exploitation probability). A traditional scanner would block deployments over this. Wardex **allows it across all 4 profiles** because the contextual risk never exceeds 0.1 — eliminating a false positive that would otherwise cost developer hours.

### 4.2 Context Transforms Decisions

The same `CVE-2020-15257` (containerd escape, CVSS 5.2) receives **3 different decisions** depending on organizational context:
- [BANK] Banco: **BLOCK** (0.9 > appetite 0.5)
- [HOSP] Hospital: **WARN** (0.5 between warn_above 0.4 and appetite 0.8)
- [SAAS] Startup: **ALLOW** (0.2 < appetite 2.0)

### 4.3 Fail-Close is Non-Negotiable

Without `wardex enrich epss`, all 237 CVEs default to EPSS 1.0 and the gate blocks 100% of them. The system never silently permits unknown risk.

### 4.4 The HITL Flow Works at Scale

237 CVEs enriched in 4.7 seconds via 5 batched HTTP calls with polite rate-limiting. The signed YAML artifact is deterministic and cacheable for CI/CD pipelines.

---

## 5. Reproducing This Test

```bash
# 1. Generate the CVE corpus
go run test/poc/gen_real_cves.go

# 2. Fetch real EPSS scores
export WARDEX_ACCEPT_SECRET="<your-secret>"
wardex enrich epss test/poc/real-250-vulns.yaml -o test/poc/real-250-enrich.yaml

# 3. Run against each profile
for ctx in bank startup dev hospital; do
  wardex --config test/poc/ctx-${ctx}.yaml \
    --gate test/poc/real-250-vulns.yaml \
    --epss-enrichment test/poc/real-250-enrich.yaml \
    test/poc/empty-controls.json
done
```

---

## 6. Files

| File | Purpose |
|---|---|
| `test/poc/gen_real_cves.go` | Generator for the 237-CVE corpus |
| `test/poc/real-250-vulns.yaml` | Generated vulnerability inputs |
| `test/poc/real-250-enrich.yaml` | Signed EPSS enrichment from FIRST.org |
| `test/poc/ctx-bank.yaml` | Bank Tier-1 (DORA) profile |
| `test/poc/ctx-hospital.yaml` | Hospital (HIPAA) profile |
| `test/poc/ctx-startup.yaml` | SaaS Startup profile |
| `test/poc/ctx-dev.yaml` | Developer Sandbox profile |
| `test/poc/high-entropy-vulns.yaml` | 20-CVE high-entropy manual set |
