# Policy Drift Dossier v1

## Outcome

WHEN a user supplies a valid local Proof Review and current plus baseline policy
snapshots, the system SHALL emit a deterministic Merge Evidence Dossier with
the commit hash, supplied-policy hashes, drift findings, exception bindings,
and one human next action.

## MUST — Functional core

### Requirements

- When a high-severity policy delta remains unexceptioned, the system shall emit `review_required` and return exit 3 for `--require-aligned` after writing the receipt.
- When a baseline is absent, the system shall emit `review_required` and return no policy-alignment claim.
- When an exception lacks one named approver, expiry, exact policy SHA, exact commit SHA, or a present finding ID, the system shall reject the exception.
- When Graph Ops finds a valid local dossier, the system shall emit a dossier node and drift nodes without calling GitHub or executing an action.
- The system shall reject any request to fetch GitHub, modify source or policy, approve, merge, sign, publish, deploy, access credentials, execute tests, or repair code.

## Acceptance

1. Matching snapshots produce `policy_aligned`.
2. A removed required check produces high deterministic drift.
3. A named, unexpired exact exception can only cover present findings.
4. Graph Ops recommends policy-drift resolution for unresolved high drift.

```gherkin
Scenario: weakened required check is review-required
Given comparable supplied policy snapshots for the same repository
And the current snapshot omits a baseline required check
When the user builds an assurance dossier with the exact Proof Review
Then the dossier reports a high drift finding and review_required
And --require-aligned exits 3 after its evidence artifacts are written
```
