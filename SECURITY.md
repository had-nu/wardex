# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v2.x    | Yes       |
| v1.9.x  | Critical fixes only |
| < v1.9  | No        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately to: **andre.ataide@proton.me**

PGP key fingerprint: `979A C8CE 8F35 7652`
Public key: https://keys.openpgp.org/search?q=979AC8CE8F357652

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment (what an attacker can achieve)
- Affected versions
- Suggested fix (optional)

**Response timeline:**
- Acknowledgement within 48 hours
- Triage and severity assessment within 5 business days
- Resolution update within 14 days for confirmed vulnerabilities

## Scope

**In scope:**
- The `wardex` CLI binary and all packages under `pkg/`
- GitHub Actions workflows in this repository
- The release pipeline (goreleaser, cosign signing, SBOM generation)
- Cryptographic operations: HMAC-SHA256 acceptance signatures, Ed25519 trust store keys, audit log integrity

**Out of scope:**
- Vulnerabilities in downstream tools that Wardex ingests (Grype, Syft) — report to those projects
- Wardex used in configurations explicitly documented as insecure (e.g., `--strict` disabled in a non-isolated environment by operator choice)

## WARDEX_ACCEPT_SECRET Key Rotation

The `WARDEX_ACCEPT_SECRET` environment variable generates HMAC-SHA256 signatures for risk acceptances. To rotate:

1. Generate a new high-entropy secret (minimum 32 bytes, base64-encoded recommended).
2. Update `WARDEX_ACCEPT_SECRET` in your CI/CD runner environments and local profiles.
3. New acceptances sign with the new key. The `signature_version` field in acceptance records traces which key produced which record.
4. Existing acceptances signed with the old key remain valid and verifiable if the old key is retained. If the old key is discarded, those acceptances cannot be re-verified — accept this trade-off consciously.

## Security Practices

- Dependencies scanned weekly by Dependabot (gomod + github-actions)
- Static analysis: `staticcheck`, `gosec`, `govulncheck` on every PR
- Race condition detection: `go test -race` on every PR
- GitHub Actions pinned to SHA256 commits, not tags
- Release binaries signed with `cosign`; SBOM generated in CycloneDX format via goreleaser
- Trust store and sealed config use Ed25519 keys; audit logs are HMAC-SHA256 signed and append-only
