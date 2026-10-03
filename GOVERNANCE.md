# Governance

hostfence is maintained by an individual. The named
[Security Maintainer](MAINTAINERS.md) owns policy decisions, vulnerability
coordination, release review, and the accuracy of security claims.

## Decisions and review

Security-relevant changes should record the threat or failure being addressed,
a reproducible test, the resulting behavior, and remaining boundaries. The
[PR template](.github/pull_request_template.md) provides that record.

- Changes that widen destination access need an explicit rationale and
  compatibility assessment from the maintainer. An allow list must not silently
  bypass address restrictions.
- Changes that tighten policy also need a migration assessment. A security fix
  can still break an application; release scope is a deliberate decision, not
  automatically a patch release.
- A maintainer-authored change may have a recorded self-review. Record any
  independent reviewer separately, only when that review actually occurred.
- Keep an unfixed bypass in the private reporting/advisory channel until a
  coordinated disclosure decision is made. Ordinary feature and documentation
  discussion can remain public.

CODEOWNERS requests review from the named owner. Requiring that approval or
successful CI is a separate GitHub branch-protection/ruleset configuration.
Repository files alone do not establish enforcement. Do not claim mandatory
two-person review for this single-maintainer project. See
[GitHub's CODEOWNERS documentation](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners).

## Releases and vulnerability handling

Use the [maintainer runbook](docs/maintainer-runbook.md) to record the candidate
commit, tests, packaged-artifact check, compatibility decision, and release
verification. Creating a local tag or passing local tests does not establish
that a remote release is published or that consumers received it.

A confirmed vulnerability may warrant a GitHub Security Advisory and a CVE
request. Neither an advisory nor a CVE is implied by a bug fix, regression test,
or maintainer role. Report affected versions and exploit conditions from
reproducible evidence; distinguish hypotheses and deployment-specific risks.

## Automation and account settings

CI runs on pushes, pull requests, or an explicit manual dispatch. It has read-only
repository permissions and performs no publication. The Dependabot file is an
inactive example; recurring update PRs and account-level security settings are
separate decisions. Dependency changes require the same review as other changes.
