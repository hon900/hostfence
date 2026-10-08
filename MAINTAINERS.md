# Maintainers

**[@hon900](https://github.com/hon900)** maintains hostfence and its integration
examples. As Security Maintainer and release owner, they define destination
policy, review security changes, coordinate reports and verify releases.

General maintenance contact: [hongoo@fastmail.com](mailto:hongoo@fastmail.com).
For suspected vulnerabilities, use
[GitHub Private Vulnerability Reporting](https://github.com/hon900/hostfence/security/advisories/new)
as described in [SECURITY.md](SECURITY.md). Avoid putting unfixed bypasses in
public issues or sending production credentials with a report.

## Responsibilities and reviewable evidence

| Responsibility | Concrete artifacts | What the evidence establishes |
| --- | --- | --- |
| Define the protection boundary | [Security policy](SECURITY.md), [architecture](docs/architecture.md) | Documented guarantees, assumptions, and known limits. |
| Maintain destination policy | [`src/`](src), [`test/security.test.js`](test/security.test.js) | Implementation and reproducible regression cases. |
| Investigate implementation failures | [Research case studies](docs/research/README.md), [`research/`](research) | Exact affected/fixed revisions, local reproductions, observed results, and bounded conclusions. |
| Demonstrate behavior | [Local playground](examples/playground), [HTTP tests](test/playground.test.js) | Deterministic examples and tests of the local interface. |
| Review changes | [PR template](.github/pull_request_template.md), [governance](GOVERNANCE.md) | A place to record impact, actual checks, and the review decision. |
| Check distributable packages | [CI workflow](.github/workflows/ci.yml), [package verifier](.github/scripts/verify-package.mjs) | Repeatable tests of the built package in an isolated consumer. |
| Triage reports and prepare releases | [Maintainer runbook](docs/maintainer-runbook.md) | An operational procedure; not evidence of past incident response. |

Each review should link its candidate commit, regression results and CI run.
The [security review](docs/security-review.md) documents the current hardening
work; [integration examples](ADOPTION.md) exercise the same policy in clients.

## Ownership and continuity

[CODEOWNERS](.github/CODEOWNERS) assigns review ownership. GitHub branch
protection or rulesets separately control required approvals and checks.
Maintainer-authored changes use the self-review record in the runbook.

There is currently no named backup maintainer in this repository. Availability
and response objectives are best effort. An ownership transfer should identify
the new contact, confirm repository access, and update this file, CODEOWNERS,
SECURITY.md, and security-insights together.
