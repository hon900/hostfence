## Problem and resulting behavior

Describe the concrete trigger, previous behavior, and expected behavior. For a
suspected unfixed vulnerability, stop and use the private reporting link in
SECURITY.md instead of including the bypass here.

## Security impact

- Does this change allow or reject any additional destination, address form, protocol, or port?
- Which boundary changes: URL parsing, hostname policy, DNS answers, address classification, transport, or packaging?
- Could an existing opt-in flag, custom resolver, or integration behave differently?

## Verification evidence

Record actual commands, runtime versions, and outcomes. Link CI results when
available; do not mark an unrun check as passed.

| Check | Command or evidence link | Result |
| --- | --- | --- |
| Regression reproducer | | |
| Core and playground tests | `npm test` | |
| Packed package import | `node .github/scripts/verify-package.mjs` | |
| Affected integration | | |

## Boundaries and release decision

- State any remaining DNS/connection gap, redirect assumptions, or network configuration requirements relevant to this change.
- Explain compatibility or migration impact and the proposed release version.
- Note whether this received independent review or maintainer self-review. Neither is implied by CODEOWNERS or green CI.
