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
| [FINANCE] **Finance** (DORA) | 0.05 | [YES] Public API | [NO] None | 1.5x | None |
| [HEALTH] **Health** (HIPAA) | 0.08 | [YES] Patient portal | [YES] Required | 1.5x | IDS/IPS (20%) |
| [SAAS] **SaaS** (Non-regulated) | 0.20 | [YES] Internal/API | [YES] Required | 1.0x | WAF + Rate Limiting (30%) |
| [UTILITIES] **Utilities** (NIS2) | 0.015 | [NO] Internal OT | [YES] Required | 1.5x | Network Segmentation (built-in) |

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
| [FINANCE] Finance | **176** | 57 | **74%** |
| [HEALTH] Health | **168** | 63 | **71%** |
| [SAAS] SaaS | **111** | 86 | **47%** |
| [UTILITIES] Utilities | **185** | 52 | **78%** |

### 3.4 Contextual Decision Divergence — Same CVE, 4 Decisions

The Risk Gate formula:

```
FinalRisk = (CVSS × EPSS) × (1 − CompensatingEffects) × Criticality × ExposureFactor
```

| CVE | CVSS | EPSS | [FINANCE] | [SAAS] | [UTILITIES] | [HEALTH] |
|---|---|---|---|---|---|---|
| **CVE-2021-44228** (Log4Shell) | 10.0 | 0.94 | **1.42** `BLOCK` | **0.25** `BLOCK` | **0.56** `BLOCK` | **0.90** `BLOCK` |
| **CVE-2024-3094** (xz backdoor) | 10.0 | 0.86 | **1.28** `BLOCK` | **0.23** `BLOCK` | **0.51** `BLOCK` | **0.81** `BLOCK` |
| **CVE-2023-38545** (curl SOCKS5) | 9.8 | 0.26 | **0.39** `BLOCK` | **0.07** `ALLOW` | **0.17** `BLOCK` | **0.23** `BLOCK` |
| **CVE-2021-44906** (minimist) | 9.8 | 0.01 | **0.01** `ALLOW` | **0.00** `ALLOW` | **0.00** `ALLOW` | **0.01** `ALLOW` |
| **CVE-2020-15257** (containerd) | 5.2 | 0.12 | **0.09** `BLOCK` | **0.02** `ALLOW` | **0.04** `BLOCK` | **0.06** `WARN` |

### 3.5 Risk Arithmetic — Log4Shell Deep Dive

**Base:** CVSS 1.0 (10/10) × EPSS 0.94 = **0.94** adjusted signal.

| Factor | [FINANCE] | [SAAS] | [UTILITIES] | [HEALTH] |
|---|---|---|---|---|
| Exposure (internet x auth x reachable) | 1.0 | 0.8 | 0.4 | 0.8 |
| Compensating (1 - effect) | 1.0 | 0.7 | 1.0 | 0.8 |
| Criticality | 1.5 | 1.0 | 1.5 | 1.5 |
| **Final Risk** | **1.41** | **0.26** | **0.56** | **0.90** |
| **vs Appetite** | 1.41 > 0.05 `BLOCK` | 0.26 > 0.20 `BLOCK` | 0.56 > 0.015 `BLOCK` | 0.90 > 0.08 `BLOCK` |

---

## 4. Key Findings

### 4.1 CVSS ≠ Risk

The CVE `CVE-2021-44906` (minimist prototype pollution) carries a CVSS of **9.8 (CRITICAL)** but an EPSS of **0.01** (1% real exploitation probability). A traditional scanner would block deployments over this. Wardex **allows it across all 4 profiles** because the contextual risk never exceeds 0.1 — eliminating a false positive that would otherwise cost developer hours.

### 4.2 Context Transforms Decisions

The same `CVE-2020-15257` (containerd escape, CVSS 5.2) receives **3 different decisions** depending on organizational context:
- [FINANCE] Finance: **BLOCK** (0.09 > appetite 0.05)
- [HEALTH] Health: **WARN** (0.06 sits in the warning band)
- [SAAS] SaaS: **ALLOW** (0.02 < appetite 0.20)

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
for ctx in finance saas utilities health; do
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
| `test/poc/ctx-finance.yaml` | Finance (DORA) profile |
| `test/poc/ctx-health.yaml` | Health (HIPAA) profile |
| `test/poc/ctx-saas.yaml` | SaaS profile |
| `test/poc/ctx-utilities.yaml` | Utilities (NIS2) profile |
| `test/poc/high-entropy-vulns.yaml` | 20-CVE high-entropy manual set |
