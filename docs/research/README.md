# SSRF research notes

Published: 2026-10-08 (Asia/Seoul). Project maintainer: [@hon900](https://github.com/hon900).

These investigations ask what a successful URL/DNS policy check actually
guarantees about the connection an application makes. Each starts with a
specific implementation failure in hostfence or its adapter, preserves a
reproducer against the affected revision, and compares it with the correction.

## Case studies

| Report | Research question | Reproduce |
| --- | --- | --- |
| [Hostname evidence is not a DNS answer](hostname-evidence-vs-dns-pinning.md) | Can an IP extracted from a hostname authorize a connection when DNS did not return it? | [Resolver experiment](../../research/hostname-pinning) |
| [A dispatch option is not a socket connector](undici-dispatch-vs-connect.md) | Does supplying a validated lookup in request options make Undici use it for the socket? | [Local transport experiment](../../research/undici-connector) |

Read the first case for address provenance and the second for enforcement at
the client boundary. The reports link the exact affected and corrected commits,
explain the experimental controls, and separate observations from deployment
risks that the experiment does not establish.

## Reproduce both experiments

From a clone of this repository, with Node.js 18.18 or later, npm, and Git:

```sh
npm run research:install
npm run research
```

The install step downloads pinned GitHub source revisions and npm dependencies.
It uses each experiment's committed lockfile and does not depend on a sibling
hostfence checkout. The historical dependencies are local research fixtures;
they are not added to the library's runtime dependencies or packed distribution.

After installation, the experiments use deterministic lookup callbacks and, in
the transport case, a server bound to loopback. They do not query public DNS or
request a public destination. A passing run asserts both the old failure and
the corrected behavior, then prints JSON evidence. Unexpected behavior fails
the command. The committed `evidence.json` files are captured observations,
not automatically refreshed success claims; a new run prints its own runtime
and results without rewriting them.

The [CI workflow](../../.github/workflows/ci.yml) repeats these experiments on
Node 18 and 26, separately from the core regression and package checks. Consult
the [actual workflow runs](https://github.com/hon900/hostfence/actions/workflows/ci.yml)
for their status; a workflow definition alone is not a passing result.

## What the research establishes

DNS rebinding, URL-parser ambiguity, and the need to verify every destination
are established SSRF topics. These reports do not claim to have discovered those
attack classes. Their contribution is identifying how this implementation lost
the distinction between address evidence and an authorized connection, then
testing the boundary with exact source revisions.

The [OWASP SSRF prevention guidance](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
provides the broader context. The experiments supply evidence about the
specific code paths described here. They are maintainer investigations of the
project's own code, not an independent audit, a CVE assignment, or evidence of
an attack on a deployed application. A simulated resolver transition is labeled
as such; no live public DNS rebinding service is used.

The [general security review](../security-review.md) covers the wider regression
suite. [Architecture](../architecture.md) explains which component enforces each
boundary, and [SECURITY.md](../../SECURITY.md) describes remaining deployment
responsibilities and private reporting.

## 한국어 안내

이 프로젝트의 연구 주제는 **“검사를 통과한 URL이 실제로도 검증된 주소에
연결되는가?”**입니다. 보고서 두 편은 알려진 SSRF 공격 기법 자체를 새로
발견했다고 주장하지 않고, 이 프로젝트의 구현에서 확인한 결함을 다룹니다.

- **첫 번째 사례:** 호스트명에 적힌 IP를 실제 DNS 응답처럼 취급하면 잘못된
  연결 주소를 선택하거나 빈 DNS 응답을 허용할 수 있습니다. 수정 전후 버전을
  같은 입력으로 비교합니다.
- **두 번째 사례:** 검증한 DNS 함수를 요청 옵션에 넣어도, 소켓을 만드는
  계층에서 사용하지 않으면 보호가 적용되지 않습니다. 로컬 서버에 도착한
  요청과 조회 함수 호출 수로 이를 확인합니다.

각 보고서의 결과는 포함된 코드로 다시 실행할 수 있습니다. 외부 서비스의
취약점이나 실제 침해 사실을 입증한 자료는 아니며, 공개된 소스의 결함과 수정
과정을 검증하는 개인 보안 연구 자료입니다.
