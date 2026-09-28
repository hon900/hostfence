# Adoption

hostfence is consumed as a GitHub package dependency (`github:hon900/hostfence`)
by the public repositories below. This is the adoption evidence for the
library: dependent repositories on a code host.

## Dependent repositories

| Repository | What it uses hostfence for |
| --- | --- |
| [hon900/hostfence-fetch](https://github.com/hon900/hostfence-fetch) | Drop-in `fetch` wrapper |
| [hon900/undici-ssrf](https://github.com/hon900/undici-ssrf) | undici dispatcher that refuses internal targets |
| [hon900/webhook-allowlist](https://github.com/hon900/webhook-allowlist) | Outbound webhook callback URL checks |
| [hon900/link-preview-safe](https://github.com/hon900/link-preview-safe) | User-supplied URL fetcher for previews |
| [hon900/egress-url-guard](https://github.com/hon900/egress-url-guard) | Edge egress allow/deny for SSRF-prone routes |

## Machine-readable pointers

- GitHub dependents graph: https://github.com/hon900/hostfence/network/dependents
- Code search for the dependency: https://github.com/search?q=hostfence+filename%3Apackage.json+user%3Ahon900&type=code
- Each consumer declares:

```json
"dependencies": {
  "hostfence": "github:hon900/hostfence#v1.2.0"
}
```
