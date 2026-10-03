# Security Maintainer runbook

This is a repeatable workflow for the individual maintainer listed in
[MAINTAINERS.md](../MAINTAINERS.md). It describes work to perform and evidence to
retain; it is not a log of completed audits or past incidents.

General maintenance: [hongoo@fastmail.com](mailto:hongoo@fastmail.com).
Suspected vulnerabilities: [private GitHub report](https://github.com/hon900/hostfence/security/advisories/new).

## 1. Triage a report

1. Preserve the report privately. Record the affected package/version, Node
   version, exact URL form, policy, resolver answers, and claimed result.
   Request a minimal fixture rather than credentials or production customer data.
2. Reproduce with an injected `lookup` and no requests to a real internal service.
   Separate URL normalization, DNS-answer classification, and the actual transport.
3. Identify the boundary: parser or policy bypass, malformed resolver handling,
   missing range, redirect behavior, resource exhaustion, or an integration's
   DNS/connection gap. A preflight check cannot prove socket enforcement.
4. Record severity rationale, known affected versions, deployment prerequisites,
   and uncertainty. Do not claim a CVE, exploit, or affected release without evidence.
5. Decide whether a private advisory/patch workspace is needed. Keep exploit
   detail private until the disclosure decision and reporter coordination are done.

A useful regression reproduces the failure before the fix, passes after it,
checks nearby allowed behavior, and uses controlled DNS/HTTP fixtures. A public
CI test should not reveal an unfixed private bypass prematurely.

## 2. Review a change

Use the [PR template](../.github/pull_request_template.md) and record:

| Area | Review prompt |
| --- | --- |
| URL parsing | Does the transport receive the normalized destination that was checked? Are unusual IPv4/IPv6 and IDNA forms consistent? |
| Policy | Are allow and deny checks cumulative? Does invalid configuration fail visibly? Which defaults become tighter or wider? |
| DNS | Are all returned addresses checked? Are invalid/empty answers and failures rejected? Is waiting bounded? |
| Transport | Are redirects and mutable request inputs handled? Is connection-time enforcement present or explicitly out of scope? |
| Resource handling | Are streams, timers, cancellation, and size limits relevant to this package covered? |
| Public claims | Do docs distinguish preflight from enforcement, local links from releases, and integration examples from adoption? |
| Supply chain | Does the lockfile change match the intended update? Are workflow actions pinned to reviewed commits? |

For a maintainer-authored change, label the review **maintainer self-review**.
If another person reviews it, record their actual review link and scope. Neither
CODEOWNERS nor CI provides independent human review by itself.

## 3. Run reproducible checks

From the core repository root:

```sh
git rev-parse HEAD
git status --short
node --version
npm --version
npm ci
npm test
node .github/scripts/verify-package.mjs
git diff --check
```

Capture the commands and their real output for the candidate commit. A dirty
working tree means the commit hash alone does not identify the tested code;
record that state and rerun after the candidate is committed.

The package verifier creates a tarball with `npm pack`, checks the file list,
installs it into an isolated consumer using `--offline --ignore-scripts`, and
runs imports plus policy checks. It removes its temporary directory afterward.
It verifies distributable contents and behavior; it does not publish or certify
the package. Its printed integrity value identifies that generated tarball.

[CI](../.github/workflows/ci.yml) runs tests and the package verifier on Node
18, 20, 22, and 24. The older majors are compatibility checks. Production users
should choose an upstream-supported runtime from the
[official Node.js release table](https://nodejs.org/en/about/previous-releases).
A configured matrix is not a completed result: attach the actual CI run and
verify each job before claiming it passed.

When an integration changes, run that repository's tests and record whether it
resolved the published dependency or a local core checkout. The local umbrella
workspace's test runner is useful for combined changes, but a local symlink must
not be presented as a released dependency.

For dependency maintenance, run `npm outdated` and `npm audit` deliberately when
reviewing an update or release. These commands contact package/advisory services;
record relevant findings and the check's scope. An empty advisory result does
not establish that the source is vulnerability-free. Review build/dev tooling
as well as runtime dependencies.

## 4. Prepare and verify a release

Complete this checklist against a specific candidate. Leave unrun items pending.

- [ ] Candidate commit and working-tree state are recorded.
- [ ] Tests and packaged-consumer checks pass; actual runtime versions and CI links are recorded.
- [ ] Affected integrations are checked using the intended core dependency, with resolution mode recorded.
- [ ] Defaults, compatibility impact, migration notes, and version choice are explained.
- [ ] README examples, exported types, package contents, security boundary, and changelog match the candidate.
- [ ] Any private report/advisory has an agreed disclosure state; no secrets or premature exploit details enter public artifacts.
- [ ] The intended tag/release destination and package version are checked for conflicts. Existing release tags will not be silently retargeted.
- [ ] Tag/release signing status is explicitly recorded. Claim a verified signature or provenance only when the corresponding artifact was generated and verified.
- [ ] After authorized publication, the remote tag's commit and release assets are verified independently from local state.
- [ ] A clean consumer installs the actual published identifier and passes the relevant smoke checks.
- [ ] Consumer dependency pins, release notes, and supported-version documentation are updated where applicable.

For a regression after release, prefer a corrective release and clear affected-
version guidance. Do not rewrite a released version or delete evidence to hide
the failure. Reproduce the rollback or upgrade path with the same package/consumer
checks before describing it as verified.

## Evidence record template

Copy this into the review or private incident record. Replace placeholders with
observed evidence; delete inapplicable fields with an explanation.

```text
Change or report:
Candidate commit / working-tree state:
Affected package versions and evidence:
Runtime and dependency resolution mode:
Failure reproducer and pre-fix result:
Implementation / regression test:
Commands and actual results:
CI run and matrix outcomes:
Packed artifact name / integrity:
Security boundary and remaining assumptions:
Compatibility / version decision:
Review: maintainer self-review | independent review link
Disclosure / advisory decision:
Signing or provenance: not performed | verified artifact and method
Remote release verification: pending | evidence
Published consumer verification: pending | evidence
Follow-up owner and concrete action:
```

## Repository controls and optional automation

CODEOWNERS declares ownership; branch rules enforce required reviews/checks only
when configured in GitHub. Verify account settings separately before stating
that a merge is protected. A single maintainer cannot supply independent approval
for their own change; do not describe an administrative exception as such review.

No scheduled scan or automatic publication is configured by this runbook.
[dependabot.yml.example](../.github/dependabot.yml.example) is inactive. If the
maintainer later chooses recurring update PRs, review its scope and cadence,
rename it to `.github/dependabot.yml`, and verify the resulting PR behavior.
Dependabot alerts/security updates are separate repository settings. Do not
claim either feature is enabled merely because a template exists.
