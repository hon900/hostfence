# hostfence

[![ci](https://github.com/hon900/hostfence/actions/workflows/ci.yml/badge.svg)](https://github.com/hon900/hostfence/actions/workflows/ci.yml)
[![security maintainer](https://img.shields.io/badge/security%20maintainer-hon900-0a7)](https://github.com/hon900/hostfence/blob/main/MAINTAINERS.md)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Know where a URL points before your server requests it.**

hostfence is a zero-runtime-dependency URL and DNS policy validator for Node.js.
It normalizes unusual address encodings, inspects every resolved address, and
returns readable rejection reasons. Use it at webhook, preview, and import
boundaries that accept a URL from a user.

Maintained by [@hon900](https://github.com/hon900), the project's named Security
Maintainer. The [maintainer runbook](docs/maintainer-runbook.md) connects policy
review, private vulnerability intake, regression evidence and release checks.
The [security review](docs/security-review.md) records the rationale behind the
current hardening work; [architecture](docs/architecture.md) explains its limits.

> **Security boundary:** this is a preflight check. It does not bind a later
> HTTP connection to the checked IP addresses, so `assert(url); fetch(url)`
> alone does **not** prevent DNS changes between validation and connection.
> Disable redirects, and use connection-level address validation or an egress
> proxy/firewall for enforcement. See [SECURITY.md](SECURITY.md).

## Try the policy lab

```bash
npm ci
npm run demo
```

The local playground demonstrates decisions with deterministic DNS fixtures.
It does not fetch the submitted destination. Run `npm test` for the regression
suite.

![Offline policy playground](docs/assets/playground.jpg)

## Install

```bash
npm install github:hon900/hostfence#v1.3.0
```

The tag pins the reviewed source and builds the TypeScript package at install
time. See [CHANGELOG.md](CHANGELOG.md) for behavior changes before updating.

## Validate a destination

```js
import { Hostfence, HostfenceError } from "hostfence";

const fence = new Hostfence({
  protocols: ["https"],
  allowedHosts: ["api.partner.example"],
  allowedPorts: [443],
  lookupTimeoutMs: 2_000,
});

try {
  const target = await fence.assert("https://api.partner.example/events");
  // target is a normalized URL. Only connect through a transport that also
  // enforces your destination policy at connection time.
  console.log(target.hostname);
} catch (err) {
  if (err instanceof HostfenceError) console.error(err.reasons);
  else throw err;
}
```

Use `check()` when you want a decision without throwing for a policy rejection:

```js
const result = await fence.check("http://127.0.0.1/admin");
// {
//   ok: false,
//   url: URL,
//   hostname: "127.0.0.1",
//   addresses: ["127.0.0.1"],
//   reasons: [/* protocol, port, allow-list and loopback failures */]
// }
```

Malformed URLs still throw `HostfenceError` with code `HOSTFENCE_INVALID_URL`.
`assert()` throws `HOSTFENCE_BLOCKED` for a valid URL rejected by policy.
DNS failures, timeouts, empty answers, and malformed resolver responses yield
`ok: false`. Already-rejected hostnames are not looked up. Duplicate DNS answers
and rejection reasons are removed.

## Policy reference

| Option | Default | Effect |
| --- | --- | --- |
| `protocols` | `["http", "https"]` | Allowed URL schemes; case and a trailing colon are normalized. |
| `allowedHosts` | Unrestricted | Exact hostname/IP allow list; `[]` denies all. DNS address checks still apply. |
| `allowedPorts` | Unrestricted | Allowed effective ports, including implicit `80`/`443`; `[]` denies all. |
| `extraDeniedHosts` | `[]` | Exact additional hostname/IP deny list. Deny rules win. |
| `extraDeniedCidrs` | `[]` | Additional IPv4 or IPv6 CIDRs; invalid configuration throws `TypeError`. |
| `lookupTimeoutMs` | `5000` | Positive integer maximum wait for DNS. |
| `lookup` | OS resolver | Async `(hostname) => string[]`; every returned address must be a valid, permitted IP. |
| `allowCredentials` | `false` | Permit URL username/password when explicitly enabled. |
| `allowPrivate` | `false` | Permit RFC1918 IPv4 ranges. |
| `allowLoopback` | `false` | Permit loopback addresses and local-style hostname suffixes. |
| `allowLinkLocal` | `false` | Permit link-local ranges, including link-local metadata IPs. |
| `allowUniqueLocal` | `false` | Permit IPv6 ULA. |
| `allowCgnat` | `false` | Permit shared IPv4 space, except the separately classified metadata IP. |
| `allowMetadata` | `false` | Permit listed metadata hostnames and `100.100.100.200`; other hostname/address checks still apply. |

Host lists use the same normalization as request URLs: case, surrounding
whitespace, trailing dots, IDNA, unusual IPv4 representations, and IPv6
compression. Supply hostnames or IP addresses, without schemes, ports, paths,
or wildcards. Checks remain cumulative; an allow list never bypasses address
restrictions. Use all opt-in flags narrowly.

Timeouts stop waiting for DNS but cannot cancel an OS lookup or an injected
resolver. A custom resolver must remain asynchronous; a blocked JavaScript
thread cannot be interrupted by the timeout.

## Default address coverage

- Loopback, RFC1918, link-local, CGNAT, IPv6 ULA, unspecified, and multicast.
- Cloud metadata names and Alibaba metadata `100.100.100.200`.
- IPv4 documentation and benchmark ranges, reserved `192.0.0.0/24` and `240/4`.
- IPv6 documentation (`2001:db8::/32`, `3fff::/20`), benchmark `2001:2::/48`,
  discard-only/dummy ranges, local-use translation, and SRv6 SID space.
- IPv4-mapped IPv6 in compressed, expanded, hexadecimal, and dotted forms.
- Invalid resolver output and scoped IPv6 answers are rejected.

`classifyAddress(ip)` returns an address category; `"public"` means it did not
match this library's blocked categories. It is not a guarantee of global
routability or the safety of a service. Reserved classifications follow the
[IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/) and
[IANA IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/)
registries conservatively; this is not a complete registry implementation.

## Contributing and security

Run `npm test` to compile TypeScript and execute the offline regression suite.
Tests cover encoded IPv4, IPv6 equivalence, range boundaries, malformed DNS,
configuration errors, hostname normalization, and timeout behavior.

The named **Lead Security Maintainer** is [@hon900](https://github.com/hon900).
See [SECURITY.md](SECURITY.md), [MAINTAINERS.md](MAINTAINERS.md), and
[ADOPTION.md](ADOPTION.md). Report suspected bypasses through
[private vulnerability reporting](https://github.com/hon900/hostfence/security/advisories/new).

## License

MIT
