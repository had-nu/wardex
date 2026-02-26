# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | ✅        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report vulnerabilities privately to: **Exemplo Empresa SA / had-nu**

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (optional)

You will receive acknowledgment within 48 hours and a resolution update within 7 days.

## Security Practices

This project follows secure development practices:

- Dependencies are scanned with [Dependabot](https://github.com/dependabot)
- Code is analyzed with `gosec` and `govulncheck`
- All PRs run security checks in CI before merge
- Race conditions are detected via `go test -race`
