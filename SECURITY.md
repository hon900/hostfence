# Security policy

## Threat model and integration contract

hostfence validates a URL and the DNS answers returned during that validation.
It rejects a destination if any returned address violates the policy. It does
not open the application's HTTP connection or control its transport.

- **DNS changes:** a subsequent HTTP client may resolve the hostname again and
  receive different addresses. `assert(url)` followed by ordinary `fetch(url)`
  does not close this time-of-check/time-of-use gap. Use `assertPin()` and pass
  `pinLookup(pin)` to the client's dialer (undici `connect.lookup`) so TCP
  targets the verified address while HTTP Host, TLS SNI, and certificate
  verification keep the original hostname. Never disable TLS verification to
  make pinning work. An egress proxy/firewall remains the deployment control.
- **Redirects:** disable automatic redirects. If the application needs them,
  validate and enforce every hop, bound the hop count, and avoid forwarding
  credentials across origins.
- **Proxies and routing:** a proxy, VPN, NAT64/translation gateway, custom route,
  or alternative HTTP stack can change the effective destination. Classification
  is not proof of where packets travel. Configure network egress controls for
  the actual deployment and any transition/translation prefixes it uses.
- **Public services:** a public IP can host an unsafe service, redirector, or
  attacker-controlled proxy. Prefer exact `allowedHosts`, HTTPS, and
  `allowedPorts` when the integration permits a small set of destinations.
- **DNS limits:** the default lookup uses the OS resolver and checks every answer
  it returns. It does not enumerate every address a hostname might return in the
  future. `lookupTimeoutMs` bounds the wait, not the lifetime of an underlying
  resolver operation. No resolver-result cache is maintained by hostfence.
- **Resource and data limits:** hostfence does not impose HTTP timeouts, body-size
  limits, concurrency limits, or redact arbitrary query strings. Configure those
  in your client and avoid logging raw URLs or errors containing sensitive input.

Policy checks are cumulative. `allowedHosts` is not a bypass for private address
checks, and opt-in flags do not override explicit deny lists. Invalid CIDRs fail
at construction rather than silently weakening a policy. URL credentials are
rejected by default. `classifyAddress()` returns `invalid` for malformed or scoped
addresses, and its `public` category is not a complete global-reachability test.

The regression suite uses injected resolver fixtures and does not contact
untrusted destinations. It tests classification and policy behavior; it does not
establish transport-level SSRF protection for an application.

Background: [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

## Named security maintainer

hostfence assigns a named **Security Maintainer** role. That person owns
vulnerability intake, embargoed fixes, GitHub Security Advisories, and
verification of security patch releases. The maintainer's workflow and evidence
are documented in [the runbook](docs/maintainer-runbook.md).

| Role | GitHub | Scope |
| --- | --- | --- |
| Security Maintainer | [@hon900](https://github.com/hon900) | Advisories, private reports, `src/` review, `SECURITY.md` |

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
| 1.4.1 and later fixes on the latest 1.x line | Yes |
| 1.4.0 | Upgrade to 1.4.1; see the [DNS pinning case study](docs/research/hostname-evidence-vs-dns-pinning.md) |
| 1.0.x–1.3.x | Upgrade to the latest 1.x release; no separate backport branch |
| < 1.0 | No |

Support is maintained by one person. Security changes are shipped on the latest
stable line; old tags remain immutable records, not patched distributions.
