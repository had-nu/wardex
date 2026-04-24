# Wardex Implementation Playbook

**Version:** v1.8.0
**Status:** Official Operational Guide
**Audience:** CISO, DevSecOps Leads, Compliance Officers, Platform Engineers

---

## Foundations: The Wardex Philosophy

Wardex is not a compliance checklist; it is a **Risk-Contextualized Decision Engine**. It operates on three core principles:
1.  **Context Over Severity**: A CVSS 10.0 in a sandbox is less critical than a CVSS 7.0 in a production authentication service.
2.  **Adaptive Security**: Existing controls (WAF, Segmentation) should actively reduce the risk score of vulnerabilities.
3.  **Intelligence-Driven**: Compliance is a data point; security posture is a trend.

---

## The Plays

### [Compliance Play 1] Initial Baseline Assessment
**Objective:** Determine the current state of ISO 27001 compliance.
**Execution:**
```bash
wardex assess --framework iso27001 ./my-current-controls.yaml
```
**Analyst's Insight:** Focus on the **Roadmap** section. Wardex prioritizes gaps not just by "missing item", but by the `BaseScore` impact. Address the top 3 items to maximize compliance gain with minimum effort.

---

### [Engineering Play 2] The Hard Stop (Release Gate)
**Objective:** Prevent high-risk deployments in CI/CD.
**Execution:**
```bash
./bin/wardex --config config.yaml --gate vulns.json ./controls.yaml
```
**Analyst's Insight:** If the gate returns `Exit Code 2`, the risk exceeds your `risk_appetite`. Do not "bypass" the gate; instead, look for **Compensating Controls** (Play 3) or **Risk Acceptance** (Play 5).

---

### [Engineering Play 3] Adaptive Security (Compensating Controls)
**Objective:** Allow a deployment with known vulnerabilities by proving mitigation.
**Execution:**
Add a `waf` or `runtime_protection` to your `wardex-config.yaml` with an `effectiveness` score (max 0.80).
**Analyst's Insight:** This play demonstrates that security is a system. A vulnerability is a hole, but a compensating control is a patch that doesn't require a code change.

---

### [Intelligence Play 4] Human-in-the-Loop (EPSS Enrichment)
**Objective:** Reduce false positives by using real-world exploit probability.
**Execution:**
```bash
wardex enrich epss scanner-output.yaml --output enriched.yaml
```
**Analyst's Insight:** EPSS is the "Intelligence" in Wardex. Many "Critical" CVSS vulnerabilities have < 1% exploit probability. Enriching data allows you to focus on what hackers are *actually* attacking.

---

### [Intelligence Play 5] Formal Risk Acceptance
**Objective:** Documented, time-bound approval for a specific risk.
**Execution:**
```bash
wardex accept request --cve CVE-2024-XXXX --expires 30d --justification "Legacy system"
```
**Analyst's Insight:** Risk acceptance is not "ignoring". It is a cryptographic commitment (HMAC-SHA256) that a human has reviewed the risk and accepted it until a specific date.

---

### [Compliance Play 8] GitOps Policy Management
**Objective:** Maintain "Compliance-as-Code" via Git.
**Execution:**
Use `wardex policy validate` as a pre-commit hook.
**Analyst's Insight:** By versioning your YAML policies, you get a full audit trail of who changed which control status and why, directly in your Git history.

---

### [Compliance Play 9] Audit Readiness (Snapshots & Deltas)
**Objective:** Prove "Continuous Improvement" to external auditors.
**Execution:**
```bash
wardex --snapshot-file jan-snapshot.json ./controls.yaml
# (3 months later)
wardex --snapshot-file jan-snapshot.json ./controls-new.yaml
```
**Analyst's Insight:** Auditors love the **Delta Section**. It shows objective growth in maturity (e.g., +15% Global Coverage), which satisfies ISO 27001 Clause 10.

---

### [Intelligence Play 11] Security Posture Assessment (v1.8.0)
**Objective:** Generate an executive-level intelligence report on organizational posture.
**Execution:**
```bash
wardex assess documented-controls.yaml implemented-controls.yaml --assets assets.yaml
```
**Analyst's Insight:** Use the **Layer Delta** to identify "Paper Security" (documented but not implemented). Use **Asset Compliance** to see which specific business units or systems are falling behind.

---

## Appendix A: Troubleshooting Guide

| Issue | Symptom | Solution |
|-------|---------|----------|
| **HMAC Mismatch** | `error: invalid signature on enrichment file` | The `WARDEX_ACCEPT_SECRET` used to sign the file does not match the one in the current environment. |
| **Catalog Not Found** | `fatal: unsupported framework: xyz` | Ensure you are using one of the supported identifiers: `iso27001`, `soc2`, `nis2`, `dora`. |
| **Empty Roadmap** | Roadmap section is missing from report | All controls in the catalog are already covered by your input. Congratulations! |
| **Fail-Close Gate** | Gate blocks even with low CVSS | Check if EPSS is missing. Wardex defaults to 1.0 (Fail-Close) if no EPSS is provided. Run `enrich epss`. |

---

## Appendix B: Governance & Risk Management Guide

### 1. Defining Risk Appetite
Risk Appetite is the threshold where Wardex triggers a `BLOCK`. Scale is [0, 1.5].
- **High (0.1 - 0.3)**: Critical Infrastructure (DORA, NIS2).
- **Moderate (0.4 - 0.7)**: Banking, Healthcare, FinTech.
- **Low (0.8 - 1.5)**: B2B SaaS, E-commerce, Internal tools.

### 2. Review Cycles
- **Quarterly**: Full Gap Analysis and Snapshot generation.
- **Monthly**: Review of expired Risk Acceptances (`wardex policy check-expiry`).
- **On-Push**: Release Gate execution for every production-bound commit.

### 3. Roles and Responsibilities
- **CISO/CRO**: Approves the `risk_appetite` value in the config.
- **Security Team**: Performs `enrich` and `accept` operations using the secret key.
- **DevOps/Engineers**: Manage the implementation of controls and respond to Gate blocks.

---
*Generated by Wardex Posture Engine. [wardex.io](https://github.com/had-nu/wardex)*
