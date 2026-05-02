# Security policy

## Named security maintainer

hostfence assigns a named **Security Maintainer** role. That person owns
vulnerability intake, embargoed fixes, GitHub Security Advisories, and
release signing for security patches.

| Role | GitHub | Scope |
| --- | --- | --- |
| Lead Security Maintainer | [@hon900](https://github.com/hon900) | Advisories, private reports, `src/` review, `SECURITY.md` |

The role is also recorded in:

- [MAINTAINERS.md](MAINTAINERS.md)
- [.github/CODEOWNERS](.github/CODEOWNERS)
- [.github/security-insights.yml](.github/security-insights.yml)

## Reporting a vulnerability

Use [GitHub Private Vulnerability Reporting](https://github.com/hon900/hostfence/security/advisories/new)
on this repository. Do not open a public issue for an unfixed SSRF bypass.

Include:

1. A URL (or generator) that `Hostfence.assert` currently allows
2. The address it resolved to, or the encoding trick used
3. Node.js version and hostfence version
4. Whether DNS rebinding, IPv4-mapped IPv6, dword/octal/hex hosts, or redirect following is involved

The Security Maintainer aims to acknowledge reports within 3 business days
and to ship a fix or advisory within 30 days for confirmed bypasses.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.2.x | Yes |
| 1.1.x | Yes |
| 1.0.x | Security fixes only |
| < 1.0 | No |
