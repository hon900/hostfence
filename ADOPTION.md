# Maintainer-owned integrations

These repositories belong to the same maintainer as hostfence. They demonstrate
integration patterns and provide places to test policy propagation. They are
listed as companion projects; independent production adoption is not tracked.

| Repository | Integration exercised |
| --- | --- |
| [hon900/hostfence-fetch](https://github.com/hon900/hostfence-fetch) | Fetch preflight policy and redirect handling. |
| [hon900/undici-ssrf](https://github.com/hon900/undici-ssrf) | Origin checks and Undici dispatch/error behavior. |
| [hon900/webhook-allowlist](https://github.com/hon900/webhook-allowlist) | Callback host policies and credential rejection. |
| [hon900/link-preview-safe](https://github.com/hon900/link-preview-safe) | HTML preview policy and response resource limits. |
| [hon900/egress-url-guard](https://github.com/hon900/egress-url-guard) | Command-line destination validation. |

The declared release dependency uses a pinned GitHub tag:

```json
"dependencies": {
  "hostfence": "github:hon900/hostfence#v1.4.0"
}
```

A dependency declaration shows intended consumption of that tag. It does not
prove that the repository has deployed the library, uses the latest working-tree
changes, or prevents SSRF at connection time. For a concrete integration claim,
record the core commit/version, consumer commit, tested runtime, dependency
resolution mode, and test result.

The umbrella workspace can link its local core checkout for development. Keep
that result separate from an installation using the declared remote tag; a
local link is not evidence that an unpublished fix is available downstream.

Public dependency discovery is available through the
[GitHub dependents graph](https://github.com/hon900/hostfence/network/dependents).
Entries there are pointers to inspect, not a verified deployment count. Add
independent adopters only with attributable evidence and permission where needed.
