# When a checked address never reaches the connector

Research date: **2026-10-08, Asia/Seoul**. Maintainer: **hon900**.

**Finding:** an unreleased `undici-ssrf` change assigned a validated DNS lookup to
request options that Undici did not use for socket creation. A real local socket
experiment shows the resulting gap and verifies the subsequent connector fix.
This is an integration defect in this project's adapter, not a vulnerability in
Undici or a newly discovered DNS attack technique.

**한국어 요약:** URL 검사 결과를 요청 옵션에 넣는 것만으로는 실제 연결 주소가
고정되지 않았습니다. 로컬 서버 실험으로 기존 코드의 잘못된 연결과 수정 코드의
차단을 비교했습니다. 과거 커밋의 의존성 설치 실패는 별개로 기록하고, 두 코드에
동일한 코어를 적용해 연결 계층의 차이만 검증했습니다.

## Question and affected scope

The research question was concrete: does the address accepted by policy become
the address used by the HTTP socket? Reading an assigned `lookup` property, or
passing a MockAgent test, cannot establish that relationship.

The affected source is the **unreleased main commit
[`babdbe5`](https://github.com/hon900/undici-ssrf/commit/babdbe5e3f8071eab991014969f0c1c572d47d7c)**.
Its package version field still says `0.9.0`, but the published Git tag
[`v0.9.0`](https://github.com/hon900/undici-ssrf/tree/9ee674f5acde58a6585158626955915bb1308223)
points to an earlier implementation documented as preflight only. This case does
not label that release as a broken socket-pinning release. The connector repair
is [`7909f71`](https://github.com/hon900/undici-ssrf/commit/7909f718c9302c053508a1a51cce2c339aa0e7b0),
tagged `v0.9.1`.

The historical commit also had a separate installation failure: its manifest
requested core `1.4.0`, while its
[lockfile](https://github.com/hon900/undici-ssrf/blob/babdbe5e3f8071eab991014969f0c1c572d47d7c/package-lock.json)
selected `1.3.0`, which lacked the imported `pinLookup` export. An import failure
does not demonstrate a transport bypass. The experiment therefore explicitly
overrides both adapters to the same core `1.4.1`, rather than pretending the
historical checkout worked unchanged.

## Mechanism and threat prerequisites

The historical interceptor called `assertPin(origin)`, then assigned
`request.connect.lookup`. Undici's
[Agent implementation](https://github.com/nodejs/undici/blob/v6.29.0/lib/dispatcher/agent.js)
constructs its per-origin Client or Pool using options retained by the Agent
constructor. The request assignment does not replace that connector. The
[connector API](https://github.com/nodejs/undici/blob/v6.29.0/docs/docs/api/Connector.md)
is the boundary that actually creates the socket.

This leaves a familiar check/use gap: policy can accept one DNS answer while the
transport obtains another. The general pattern is described by
[CWE-367](https://cwe.mitre.org/data/definitions/367.html); the contribution here
is tracing and reproducing its manifestation in this adapter.

An exploitable deployment would require an attacker-controlled destination, a
different transport resolution after validation, a new connection, and network
reachability to the disallowed destination. Existing firewall rules, fixed
destination lists, or a separate enforcing connector can change that outcome.
No production exploit, victim, or external deployment is established here.

## Controlled comparison

The [standalone fixture](../../research/undici-connector/package.json) installs
both adapter implementations directly from immutable Git SHAs under npm aliases.
It copies no implementation source. Its explicit core override and committed
lockfile define this composition:

| Component | Historical experiment | Fixed experiment |
| --- | --- | --- |
| Adapter | `babdbe5e3f8071eab991014969f0c1c572d47d7c` | `7909f718c9302c053508a1a51cce2c339aa0e7b0` |
| Shared core override | `1.4.1`, `3d450931930a5a69f97b6ef27eb9b3f527b3d862` | Same |
| Transport | Undici `6.29.0` | Same |

The runner checks lockfile commits, the installed core version, and shared module
identity between both adapters and the controlled core. A silent nested core
replacement fails those assertions. Using a plain `.invalid` hostname avoids
the separate embedded-address behavior changed in core `1.4.1`.

Each scenario starts an HTTP server bound exclusively to `127.0.0.1`. The public
address `93.184.216.34` is a policy input only. In the historical scenario, a
constructor-level lookup deterministically returns loopback, standing in for a
second resolver. An observer probes the assigned request lookup without opening
a socket, then counts actual transport calls to it. Its replacement fails closed
if invoked, preventing that public answer from becoming a network target.

For the fixed negative case, policy lookup returns public first and loopback on
the connection-time check. The positive control explicitly allows loopback and
returns loopback twice. Every observed socket and HTTP request is local. This is
an injected resolver simulation, **not an actual public-DNS rebinding attack**.

## Reproduction and observed results

From the repository root, with Git, npm, and the selected Node runtime installed:

```sh
cd research/undici-connector
npm ci
npm test
```

Repeat with Node 18 and Node 26. Installation downloads dependencies; the test
scenarios require no external HTTP service or DNS server. `npm --silent test`
prints the same result as plain JSON. Tests do not overwrite the committed
[evidence snapshot](../../research/undici-connector/evidence.json).

| Scenario | Policy lookups | Request lookup transport calls | Local sockets / HTTP requests | Result |
| --- | ---: | ---: | ---: | --- |
| Historical adapter, strict defaults | 1 | 0 | 1 / 1 | Public pin ignored; loopback reached |
| Fixed agent, public then loopback | 2 | Not applicable | 0 / 0 | Rejected before connection |
| Fixed agent, explicit loopback test policy | 2 | Not applicable | 1 / 1 | Validated route connected |

Both recorded runtime runs satisfy all assertions. Evidence includes runtime,
source and lockfile hashes, commits, lookup counts, socket counts, request counts,
and the fixed error code. The historical constructor lookup is called once,
while the request-level lookup receives zero transport calls: this is the direct
evidence that inspecting request options alone missed.

## Repair and remaining limits

The repair preserves `createSsrfInterceptor` as a documented preflight API and
adds `createSsrfAgent`. Its owned connector checks the actual connection hostname
again and supplies the selected validated address through `buildConnector`.
The original hostname remains the HTTP and TLS identity; routing overrides are
rejected. The [fix's regression tests](https://github.com/hon900/undici-ssrf/blob/7909f718c9302c053508a1a51cce2c339aa0e7b0/test/agent.test.js)
also cover certificate verification and routing-header rejection.

This fixture evaluates fresh HTTP connections on one transport version. It does
not establish complete coverage of TLS, IPv6, redirects, proxies, pooled-socket
lifecycle, or arbitrary interceptor composition. The positive control's loopback
exception is deliberately unsuitable as a production default. No CVE assignment,
independent adoption, or external validation is claimed. The reusable lesson is
to validate a security invariant at the resource-creation boundary and retain
measured evidence of the resource actually used.
