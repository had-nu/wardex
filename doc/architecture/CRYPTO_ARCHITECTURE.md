# Wardex Cryptographic Architecture 2026
**Version**: 1.0 (March 2026)
**Scope**: Risk Acceptance Integrity Module (`pkg/accept/signer`)

## 1. Objective and Threat Model
The Wardex Release Gate natively blocks builds that violate enterprise risk appetite thresholds. To gracefully manage exceptions, developers can request Risk Acceptances. Because these acceptances bypass security controls and permit known vulnerabilities to ship to production, their integrity is the most critical security boundary in the Wardex ecosystem.

### Threat Model
The architecture is designed to defend against the following threats:
1.  **Tampering (The Inside Job)**: A malicious insider modifies `wardex-acceptances.yaml` manually to inject an unapproved CVE exception or alter an expiration date.
2.  **Repudiation**: A developer claims they did not accept a specific risk.
3.  **Cross-Context Replay**: A risk acceptance signed in a "dev" repository context is illicitly copied to bypass the gate in a "prod" repository.

## 2. Signature Specification (HMAC-SHA256)
All Risk Acceptances are cryptographically bound using Hash-based Message Authentication Codes (HMAC) utilizing the `SHA-256` hashing algorithm.

### 2.1 The Secret Key (`WARDEX_ACCEPT_SECRET`)
The secret key must be exactly 32 bytes (256 bits) of high-entropy data. 
It is injected into the CI/CD environment runtime exclusively as an environment variable and is **never** written to disk during gate evaluation.
*   **Derivation**: N/A (Symmetric Key)
*   **Rotation**: Supported manually holding older keys in an array (pending automated JWK rotation).

### 2.2 The Canonical Payload
To prevent tampering, the payload hashed by the HMAC must represent the exact semantic state of the acceptance. Wardex extracts the following fields, in strict order, formatted precisely as a delimiter-separated string:
`"{ID}|{CVE}|{AcceptedBy}|{Justification}|{ExpiresAt_UnixNano}|{Ticket}|{ReportHash}"`

*Rationale for fields:*
*   **ID**: Prevents duplication.
*   **CVE**: The core subject of the exception.
*   **AcceptedBy**: Non-repudiation tracker.
*   **Justification & Ticket**: Binds the business context to the signature.
*   **ExpiresAt**: Prevents indefinite exploitation of the exception.
*   **ReportHash**: Cross-Context Replay protection. Binds the signature to a specific point-in-time compliance report.

### 2.3 Verification Flow
When `wardex` evaluates `wardex-acceptances.yaml`:
1.  It loads the 256-bit symmetric key from the environment.
2.  It reads the YAML payload, stripping the stored `Signature` field.
3.  It reconstructs the Canonical Payload string.
4.  It generates a localized HMAC-SHA256 hash.
5.  It performs a **Constant-Time Comparison** (`subtle.ConstantTimeCompare`) against the stored signature to prevent timing-based side-channel attacks.

## 3. Storage and Immutability
Risk Acceptances are stored in plaintext YAML (`wardex-acceptances.yaml`) to ensure they remain human-readable and git-compatible for code reviews. Their security is guaranteed by the mathematically irreversible HMAC process, not by encryption. 

### Write-Once / Append-Only 
The application logically prevents the internal modification of an acceptance once signed. If an acceptance must be invalidated before its expiration date, it must be explicitly **Revoked**, which issues a new cryptographically verifiable revocation entry in the `wardex-accept-audit.log`.
