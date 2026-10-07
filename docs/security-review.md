# Security review: destination policy hardening

This review records code-level findings, fixes and remaining boundaries. It is a
maintainer review of this codebase, not an independent audit, a penetration test
of a deployed service, or a CVE advisory. The inputs below are local fixtures.

## Findings and evidence

| Area | Previous behavior | Change | Reproduction / evidence |
| --- | --- | --- | --- |
| Resolver output | An invalid address string could fall through as public | Require an array of valid IP literals; reject malformed, scoped and empty answers | `test/security.test.js`, malformed DNS cases |
| IPv6 equivalence | Some expanded dotted mapped forms were parsed incorrectly | Expand valid IPv6 consistently before identifying mapped IPv4 | `test/security.test.js`, mapped address and loopback vectors |
| Denied CIDRs | Invalid entries could be silently ignored | Reject malformed policy at construction | `test/security.test.js`, CIDR validation cases |
| Address coverage | Reserved IPv4 and some IPv6 special-use space fell through | Add explicit reserved/documentation/benchmark ranges | `test/security.test.js`, boundary vectors |
| Host policy | Request and policy hostname normalization differed | Use the same canonicalization for both | `test/security.test.js`, IDNA, numeric and trailing-dot cases |
| Resource limits | Resolver waiting had no library deadline | Bound awaiting the resolver; fail closed on timeout | `test/security.test.js`, stalled and rejected resolver cases |
| Destination controls | No effective-port restriction or default userinfo rejection | Add `allowedPorts`, `allowCredentials` and explicit policy validation | `test/security.test.js`, port and credentials cases |

All fixes retain the existing `check()` and `assert()` entry points. Tightened
validation is a behavior change: consumers relying on URL credentials, invalid
configuration, reserved addresses or unbounded resolution must review migration
notes before updating.

## Integration review

The maintainer also owns the repositories listed in [ADOPTION.md](../ADOPTION.md).
Their companion changes apply the same decisions at application boundaries:

- **hostfence-fetch:** reject automatic redirects; snapshot a native Request
  before asynchronous validation and check cancellation before transport.
- **link-preview-safe:** bound waiting and streamed bytes; reject non-HTML and
  failed HTTP responses; cancel rejected bodies; treat extracted metadata as
  untrusted output.
- **webhook-allowlist:** forward the full policy, keep credentials prohibited,
  and expose structured checks for registration and retry workflows.
- **undici-ssrf:** return a synchronous dispatcher acceptance value and deliver
  asynchronous validation failures through the handler. Queued validation does
  not propagate downstream backpressure.
- **egress-url-guard:** return structured batch decisions and stable exit codes,
  including malformed URL and input failure cases.

These are code-reviewed integration examples from one maintainer. They do not
establish independent adoption or production deployment history.

## Explicitly unresolved at this layer

`assert()` alone does not pin a later HTTP connection. `assertPin()` plus
`pinLookup()` close the DNS TOCTOU for clients that honor the pin. Proxy
routing, public redirectors, TLS enforcement, application authorization and
deployment egress rules remain integration concerns. See [SECURITY.md](../SECURITY.md).

## Reproduce the review

```sh
npm ci
npm test
npm pack --dry-run
npm run demo
```

The playground exercises the compiled engine with fixed DNS records. Its HTTP
tests also verify body limits, input types, static-path restrictions, credential
redaction, and Host/Origin checks. Test each companion package from its own
checkout before releasing a coordinated update.

Use the PR template to record commands and results for future changes, including
any expected result that changes. Do not copy a previous passing result forward
without rerunning the relevant checks.
