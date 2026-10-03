# Changelog

## 1.3.0 — 2026-10-03

- Reject malformed DNS responses, scoped addresses, and stalled lookups; deduplicate DNS records.
- Fix expanded/dotted IPv4-mapped IPv6 and alternate IPv6 loopback/unspecified representations.
- Block reserved IPv4 space and additional IPv6 documentation, benchmark, and special-use ranges.
- Normalize host policy entries with request URLs, including IDNA, numeric IPv4, and IPv6 compression.
- Reject invalid CIDR and destination policy configuration instead of silently ignoring it.
- Add `allowedPorts`, `allowCredentials`, and `lookupTimeoutMs`; URL credentials are now denied by default.
- Keep malformed URL error codes and the existing `check()` / `assert()` result shapes.
- Document the DNS validation/connection gap, redirect controls, and network enforcement requirements.
- Add an offline security regression suite and a local policy playground.
- Add the maintainer review/runbook, package-install verification in CI, and a security-impact PR template.

## 1.2.0 — 2026-09-28

- Block decimal, hex, and octal IPv4 dword hostnames (`http://2130706433/`).
- Treat Alibaba metadata `100.100.100.200` as a metadata address.
- Document the named Security Maintainer role in OpenSSF security insights.

## 1.1.0 — 2026-08-20

- Add `allowedHosts` allow-list mode.
- Add `extraDeniedCidrs` and `extraDeniedHosts`.
- CI on Node 18, 20, and 22.

## 1.0.0 — 2026-07-16

- Stable `Hostfence.check` / `Hostfence.assert` API.
- Default-deny for loopback, RFC1918, link-local, ULA, CGNAT, multicast,
  documentation ranges, and cloud metadata hostnames.
- DNS lookup of every A/AAAA record to catch rebinding.

## 0.9.0 — 2026-06-08

- Policy flags: `allowPrivate`, `allowLoopback`, `allowLinkLocal`,
  `allowUniqueLocal`, `allowMetadata`, `allowCgnat`.

## 0.3.0 — 2026-04-10

- Injectable `lookup` for tests and custom resolvers.

## 0.2.0 — 2026-03-22

- Cloud metadata hostname denylist.
- IPv4-mapped IPv6 handling.

## 0.1.0 — 2026-02-18

- Initial IPv4/IPv6 classification and URL protocol allow list.
