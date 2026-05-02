# Governance

hostfence is a small security library. Decisions about default-deny ranges
and DNS policy are made by the named Security Maintainer.

## Roles

**Security Maintainer.** Named in `MAINTAINERS.md`. Owns vulnerability
response, embargo, and the default policy in `src/ranges.ts` /
`src/classify.ts`. CODEOWNERS requires this role on security-sensitive
paths.

**Core maintainer.** Ships releases, CI, and documentation.

## Policy changes

Widening what `Hostfence` allows (for example permitting CGNAT or
link-local addresses by default) needs an issue labeled `policy` and
approval from the Security Maintainer. Tightening blocks can ship in a
patch release.

## Advisories

Advisories are filed as GitHub Security Advisories by the Security
Maintainer. CVE requests, if any, go through GitHub's CVE numbering.
