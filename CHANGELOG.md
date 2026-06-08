# Changelog

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
