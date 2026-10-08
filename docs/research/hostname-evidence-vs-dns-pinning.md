# When hostname evidence became a connection target

Prepared: **2026-10-08**. Scope: **maintainer self-review** of Hostfence.

**한국어 요약:** v1.4.0은 호스트명에서 추정한 공개 IP를 실제 DNS 응답보다 먼저 연결 대상으로 선택했습니다. DNS 응답이 비어 있어도 그 추정값만으로 요청을 허용했습니다. 이 사례는 두 버전을 같은 로컬 입력으로 비교하며, 내부망 침투나 실제 서비스 공격을 입증한 것은 아닙니다.

## Research question

Can an address extracted from a hostname safely serve both as a reason to
reject that hostname and as the destination a client should connect to?

Hostfence recognizes address-bearing names such as `8.8.8.8.nip.io`. That is
useful when rejecting obvious loopback or private-address variants before DNS.
The v1.4.0 implementation also treated an allowed hostname hint as a resolved
address. This conflated evidence about a name with evidence about its actual
destination.

The distinction matters because `check()` returns a `DestinationPin` that a
transport can use instead of resolving the name again. A pin should identify a
permitted IP literal from the URL or an address returned by the checked
resolver. Passing address classification alone does not establish that origin.

## Revisions and source evidence

| Role | Version | Immutable source |
| --- | --- | --- |
| Reproduced defect | 1.4.0 | [`4df2308`](https://github.com/hon900/hostfence/blob/4df230828e7a8b3055c9ffba8ff2b982be313a03/src/hostfence.ts#L74-L125) |
| Verified correction | 1.4.1 | [`3d45093`](https://github.com/hon900/hostfence/blob/3d450931930a5a69f97b6ef27eb9b3f527b3d862/src/hostfence.ts#L75-L126) |

The [fix commit](https://github.com/hon900/hostfence/commit/3d450931930a5a69f97b6ef27eb9b3f527b3d862)
separates these two address sources. The accompanying
[regression cases](https://github.com/hon900/hostfence/blob/3d450931930a5a69f97b6ef27eb9b3f527b3d862/test/bypass-corpus.test.js#L107-L155)
cover mismatched answers, empty answers, explicit loopback exceptions, extra
denied CIDRs, and private DNS results.

This report reproduces the defect in v1.4.0 and its correction in v1.4.1. It does
not infer a wider affected-version range. The report date records this write-up;
it is not a claim that this research was published before the linked commits.

## Threat model and method

The application accepts a URL and uses Hostfence's decision or returned pin.
An input may contain a recognized wildcard-DNS hostname. Its resolver returns
an address different from the encoded hint, or an empty array. The latter is
an accepted return shape for the injectable resolver API. These conditions are
controlled in the fixture; they are not claims about any public DNS provider's
current behavior.

Each revision receives the same URL, default address policy, and injected
resolver answers. Only the package revision changes. The fixture imports both
packages installed from exact GitHub commit identifiers, checks their manifest
versions and lockfile resolution, and rejects workspace/package symlinks. It
asserts the decisions, selected pins, resolver-call counts, and rejection reasons
before printing machine-readable JSON.

The reproduction sends no HTTP requests and makes no public DNS queries.
Public and private IPs appear only as fixture strings. Installing dependencies
does contact GitHub and the npm registry and builds the packages. A successful
test means the observed before/after behavior matches the assertions, including
the expected failure behavior in the older implementation.

## Observed outcomes

| Input and injected answer | v1.4.0 | v1.4.1 |
| --- | --- | --- |
| `8.8.8.8.nip.io` → `1.1.1.1` | Allows; pins **8.8.8.8** | Allows; pins **1.1.1.1** |
| `8-8-8-8.sslip.io` → empty array | Allows; pins **8.8.8.8** | Rejects; no pin |
| Public hostname hint → `127.0.0.1` | Rejects; no pin | Rejects; no pin |
| Public hostname hint → public + private answers | Rejects; no pin | Rejects; no pin |
| `127.0.0.1.nip.io` → resolver must not run | Rejects before DNS | Rejects before DNS |
| `ordinary.invalid` → `1.1.1.1` | Allows; pins **1.1.1.1** | Allows; pins **1.1.1.1** |

The private-answer controls are material: a permitted hostname hint did not
override an actual forbidden DNS answer in either revision. The ordinary-name
control also shows that the fix retains an allowed lookup path.

## Root cause and correction

In v1.4.0, `addresses` was initialized with hostname-embedded IPs. DNS answers
were appended to that array. Every collected address was classified, and the
first allowed entry became the pin. A public hint therefore took precedence
over the real resolver result. The same seeded array prevented the empty-answer
check from detecting that DNS had supplied nothing.

Version 1.4.1 tracks `resolvedAddresses` separately. Classification still checks
the combined evidence, preserving early rejection of suspicious hostname hints.
Pin construction uses only the first verified resolver answer, or the URL's IP
literal. An otherwise permitted name with no resolved address fails closed.
The public `addresses` field remains diagnostic evidence; it is not a list of
interchangeable connection targets.

## Reproduce and inspect the evidence

From the repository root, with Node.js 18.18 or later, npm, and Git:

```sh
cd research/hostname-pinning
npm ci && npm test
```

The [fixture](../../research/hostname-pinning/reproduce.mjs) checks six cases
against both revisions. `npm test` prints JSON and does not overwrite saved
evidence. To capture a separate run:

```sh
npm run --silent test > /tmp/hostname-pinning-result.json
```

The checked-in [Node 26 evidence](../../research/hostname-pinning/evidence.json)
and [Node 18 evidence](../../research/hostname-pinning/evidence-node18.json)
record actual runs, exact source commits, runtime versions, and per-case
results. Both were generated after installing the locked dependencies in a
clean, separate directory. Runtime checks used Node 26.10.0 and 18.20.8; this
does not claim an execution on every supported Node release. Installation
requires network access, while the comparison itself is deterministic apart
from its timestamp and runtime metadata.

## Impact and limits

The demonstrated failures are selection of an address absent from the DNS
answer and authorization without any successful DNS answer. A transport that
honors the old pin could attempt a different allowed destination. Actual impact
depends on resolver behavior, transport configuration, and TLS certificate
verification, which this fixture does not exercise.

No internal-network access, credential theft, public-provider compromise, or
deployed exploitation is established here. No CVE or independent audit is
claimed. DNS validation and connection pinning are established SSRF defense
concepts; this work contributes a reproducible analysis of a defect in this
implementation. The broader lesson is to preserve the provenance of security
evidence: a heuristic that can justify rejection should not silently become
authority to connect.
