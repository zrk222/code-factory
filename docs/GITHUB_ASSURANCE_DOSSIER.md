# GitHub Assurance Dossier

The Merge Evidence Dossier is a local, deterministic comparison between a
commit-bound FactoryLine Proof Review and two **supplied** GitHub policy
snapshots. It gives a senior reviewer one evidence packet before a merge
decision.

It does not call GitHub, fetch a live configuration, change a ruleset, approve
or merge a pull request, sign anything, run tests, repair code, or access a
credential. A supplied snapshot is evidence of the supplied export only.

## The flow

```text
local Proof Review + current policy export + optional baseline export
  -> deterministic policy-drift findings
  -> named, expiring exception check
  -> Merge Evidence Dossier
  -> human merge decision
```

Create a normal local proof-review packet first, then validate a policy export:

```bash
factory github policy-snapshot policy-current.json --json
factory github assurance-dossier \
  --proof-review .factory/github/github-proof-review.json \
  --policy-snapshot policy-current.json \
  --baseline-policy-snapshot policy-baseline.json \
  --out-dir .factory/github-assurance \
  --require-aligned --json
```

`--require-aligned` writes the dossier first, then exits `3` when the baseline
is missing or an unexceptioned high-severity policy delta remains. This makes a
CI gate explicit without hiding the evidence that led to it.

## What the v1 snapshot detects

For a ruleset present in both exports, the comparison reports high-severity
drift if an active ruleset is weakened, signed-commit protection is removed,
force pushes are enabled, a required check or workflow disappears, or a bypass
actor is added. A missing baseline is visible as `review_required`; it is never
treated as alignment. New rulesets are informational.

The snapshot contract is intentionally narrow and schema-validated. Expand it
through a versioned data contract and tests, not a prompt or heuristic.

## Exceptions

An exception is accepted only when it has one named approver, an expiry no more
than 31 days away, the exact current policy SHA-256, the exact PR head SHA, and
only drift finding IDs present in the dossier. It never grants a merge or a
policy bypass. Graph Ops projects the dossier and each finding as read-only
nodes, with `resolve_policy_drift` as the next action when high drift remains.

## Commercial boundary

The local dossier is part of the free proof-first core. The future GitHub
Assurance Seat may package policy bundles, organization workflows, governed
exceptions, and support only after its public activation gates are satisfied.
It is not an active checkout or entitlement. See
[the GitHub per-seat plan](GITHUB_MONETIZATION_2026.md).
