# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report vulnerabilities privately to: **Exemplo Empresa SA / had-nu**

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (optional)

You will receive acknowledgment within 48 hours and a resolution update within 7 days.

## WARDEX_ACCEPT_SECRET Key Rotation

The `WARDEX_ACCEPT_SECRET` environment variable is used to generate HMAC-SHA256 signatures for risk acceptances. To safely rotate this key:

1. Generate a new high-entropy secret string.
2. Update `WARDEX_ACCEPT_SECRET` in your CI/CD runner environments or local profiles.
3. New acceptances will be signed with the new key. Wardex schemas support a `signature_version` field to help audit and trace which key generated which record.

## Security Practices

This project follows secure development practices:

- Dependencies are scanned with [Dependabot](https://github.com/dependabot)
- Code is analyzed with `gosec` and `govulncheck`
- All PRs run security checks in CI before merge
- Race conditions are detected via `go test -race`
