# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in GhostRing, **please do not open
a public issue.** Instead, email the maintainer directly:

**bauratynov@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

## Response Timeline

- **Acknowledgement:** within 48 hours
- **Assessment:** within 7 days
- **Fix or mitigation:** within 30 days for critical issues

## Scope

This policy covers the GhostRing hypervisor core (`src/`), loaders
(`loader/`), and agents (`agent/`). Third-party code in `reference/` is
not covered — report those issues to the respective upstream projects.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Responsible Disclosure

We ask that you give us reasonable time to fix the issue before any public
disclosure. We will credit reporters in the release notes unless they
prefer to remain anonymous.
