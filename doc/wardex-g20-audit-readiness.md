# Wardex: Third-Party Audit Readiness & Non-Repudiation Architecture

*Last Updated for v1.6.0 | Aligned for SOC 2 (CC7.1), ISO 27001 (A.8), and DORA.*

## Executive Summary
Wardex is designed to act as a **Risk-Based Release Gate** for modern CI/CD pipelines. Because Wardex has the authority to block or allow deployments based on acceptable risk scores, it operates at a high level of privilege. For organizations undergoing rigorous third-party audits (SOC 2 Type II, ISO 27001, FedRAMP), simply having a tool calculate risk is insufficient; the tool must mathematically prove its integrity to prevent insider threat logic bypassing.

This document details the cryptographic boundaries, non-repudiation mechanics, and Role-Based Access Controls (RBAC) engineered into Wardex to satisfy external auditor scrutiny.

## 1. Cryptographic Non-Repudiation (The Risk Acceptance Flow)
The most sensitive action in Wardex is **Risk Acceptance**, where a vulnerability that exceeds the `warn_above` threshold is forcibly bypassed by a human operator so a deployment can proceed.

To prevent developers from silently accepting risks, Wardex employs an **HMAC-SHA256 signature chain**:
1. **The Request:** When an engineer requests an exception (`wardex accept request`), Wardex generates a JSON payload containing the CVE ID, the business justification, the exact expiration timestamp, the system configuration hash, and the requesting identity (`GITHUB_ACTOR`).
2. **The Signature:** A security officer (holding the `signing_secret`) must run `wardex accept grant`. This generates an `HMAC-SHA256` signature of the payload.
3. **The Audit Trail:** The signed artifact is written to `wardex-acceptances.yaml` (the local state) AND an immutable append-only `wardex-accept-audit.log`.
4. **The Verification Gate:** During CI/CD execution, `wardex` reads the `wardex-acceptances.yaml`. For every risk acceptance, it recalculates the HMAC. **If a single byte (like the expiration date or justification) has been tampered with by a developer, the HMAC fails, the acceptance is discarded, and the pipeline halts with an error (`Code 11: Tampered Acceptance`).**

*Auditor Proof:* You can provide the auditor the `wardex-accept-audit.log` and the `signing_secret` to independently verify the cryptographic chain of custody for every bypassed vulnerability in the past year.

## 2. True Role-Based Access Control (RBAC) via Context Profiles
While the baseline Wardex configuration (`wardex-config.yaml`) defines a global `RiskAppetite` limit (e.g., 8.0), some deployments (like legacy APIs or internal sandboxes) might have a higher justified tolerance for risk via `--profile <name>`.

To prevent unauthorized profile assumption, Wardex v1.6.0 introduces **True RBAC**:
*   The `wardex-config.yaml` defines `allowed_actors: ["frontend-lead", "devops-machine"]` for each profile.
*   Upon execution, Wardex interrogates the environment variables (preferring `WARDEX_ACTOR`, falling back to `GITHUB_ACTOR` or `USER`).
*   If the executing identity is not cryptographically matched to the `allowed_actors` array, Wardex generates an `[RBAC VIOLATION]` log, rejects the `--profile` override, and evaluates the software against the strictest baseline policy.

*Auditor Proof:* This creates an enforced "Least Privilege" execution model for the Release Gate itself, ensuring developers cannot circumvent organizational risk constraints.

## 3. Configuration Drift Protection (Config-Audit Hashing)
When a risk is accepted, the acceptance is cryptographically locked not just to the CVE, but to the **hash of the `wardex-config.yaml` at the exact time of signing**. 

If a malicious actor changes the baseline organizational `RiskAppetite` to make it more permissive, the hash changes. All existing risk acceptances instantly transition to a `Stale` state and become invalid. This enforces a continuous re-evaluation of risk whenever policy shifts occur.

## 4. SIEM Verification & Telemetry
Wardex supports telemetry forwarding (`wardex accept verify-forwarding`) to push JSON logs to enterprise SIEM backends (Splunk, Datadog) over verified TCP/HTTP connections. By enforcing `net.DialTimeout` SLA checks, pipelines can be configured to fail closed if the SIEM telemetry cluster is unreachable, guaranteeing zero blind spots in audit logging.
