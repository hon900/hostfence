# Maintainer-owned integrations

These repositories belong to the same maintainer as hostfence. They demonstrate
integration patterns and provide places to test policy propagation. They are
listed as companion projects; independent production adoption is not tracked.

| Tagged example | Locked core | Integration exercised |
| --- | --- | --- |
| [hostfence-fetch 1.3.1](https://github.com/hon900/hostfence-fetch/tree/v1.3.1) | 1.4.1 | Per-request validation, connection pinning, and redirect handling. |
| [undici-ssrf 0.9.1](https://github.com/hon900/undici-ssrf/tree/v0.9.1) | 1.4.1 | Origin checks; an owned agent with connection-time validation and pinning. |
| [webhook-allowlist 2.1.0](https://github.com/hon900/webhook-allowlist/tree/v2.1.0) | 1.3.0 | Callback host policies and credential rejection. |
| [link-preview-safe 0.5.0](https://github.com/hon900/link-preview-safe/tree/v0.5.0) | 1.3.0 | HTML preview preflight policy and response resource limits. |
| [egress-url-guard 1.1.0](https://github.com/hon900/egress-url-guard/tree/v1.1.0) | 1.3.0 | Command-line destination validation. |

These rows describe the linked immutable tags, not each repository's current
`main` branch. The three 1.3.0 examples do not include core 1.4.x pinning.

The fetch 1.3.1 and Undici 0.9.1 integrations declare this core dependency:

```json
"dependencies": {
"hostfence": "github:hon900/hostfence#v1.4.1"
}
```

The other integration repositories have their own versioned dependency pins;
inspect their manifests and lockfiles when evaluating a particular release.
The [research experiments](docs/research/README.md) instead use exact historical
commits to compare failures and fixes.

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
