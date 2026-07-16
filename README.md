# hostfence

[![ci](https://github.com/hon900/hostfence/actions/workflows/ci.yml/badge.svg)](https://github.com/hon900/hostfence/actions/workflows/ci.yml)
[![security maintainer](https://img.shields.io/badge/security%20maintainer-hon900-0a7)](https://github.com/hon900/hostfence/blob/main/MAINTAINERS.md)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

SSRF guard for Node.js. Run it **before** `fetch`, undici, or any HTTP client
that takes a user-supplied URL. hostfence refuses loopback, RFC1918,
link-local, unique-local, CGNAT, multicast, documentation ranges, cloud
metadata endpoints, and DNS-rebinding responses where any record is internal.

## Install

```bash
npm install github:hon900/hostfence#v1.2.0
```

## Usage

```js
import { Hostfence, HostfenceError } from "hostfence";

const fence = new Hostfence();

export async function safeFetch(url, init) {
  await fence.assert(url);
  return fetch(url, init);
}

try {
  await fence.assert("http://169.254.169.254/latest/meta-data");
} catch (err) {
  if (err instanceof HostfenceError) {
    console.error(err.reasons);
  }
}
```

`check()` returns a structured result if you want to log and continue:

```js
const result = await fence.check(req.body.callbackUrl);
if (!result.ok) {
  return res.status(400).json({ reasons: result.reasons });
}
```

## What it blocks by default

- Protocols other than `http` and `https`
- Loopback (`127.0.0.0/8`, `::1`, `localhost`)
- Private (`10/8`, `172.16/12`, `192.168/16`, IPv6 ULA)
- Link-local (`169.254/16`, `fe80::/10`) including IMDS
- CGNAT `100.64/10` and Alibaba metadata `100.100.100.200`
- IPv4-mapped IPv6 (`::ffff:127.0.0.1`)
- Decimal / hex / octal dword hosts (`http://2130706433/`)
- Metadata hostnames (`metadata.google.internal`, Kubernetes in-cluster DNS)
- Any resolved A/AAAA record that falls in those ranges (rebinding)

Policy knobs: `allowPrivate`, `allowLoopback`, `allowLinkLocal`,
`allowUniqueLocal`, `allowMetadata`, `allowCgnat`, `allowedHosts`,
`extraDeniedCidrs`, `extraDeniedHosts`, and an injectable `lookup`.

## Security maintainer

The named **Lead Security Maintainer** for this project is
[@hon900](https://github.com/hon900). See [SECURITY.md](SECURITY.md) and
[MAINTAINERS.md](MAINTAINERS.md). Bypass reports go through
[private vulnerability reporting](https://github.com/hon900/hostfence/security/advisories/new).

## Adoption

Public dependents are listed in [ADOPTION.md](ADOPTION.md).

## License

MIT
