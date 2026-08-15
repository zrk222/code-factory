# Code Factory 0.34.0

## Merge Evidence Dossier

`factory github assurance-dossier` joins a commit-bound local Proof Review with
schema-validated, **supplied** GitHub policy snapshots. It produces a
hash-bound JSON, Markdown, and Mermaid dossier showing deterministic ruleset
drift, named expiring exceptions, and one next human action.

- A missing baseline is visibly `review_required`, never assumed aligned.
- Weakening an active ruleset, removing signed-commit protection, enabling
  force pushes, removing required checks/workflows, or adding a bypass actor
  is a high-severity finding.
- `--require-aligned` returns exit code 3 after writing the evidence when a
  baseline or high-drift review still needs human action.
- The feature has no network, source-write, test-execution, policy-write,
  approval, merge, signing, publication, deployment, or credential authority.

## Graph Ops Proof Observatory

The Graph Ops Studio surface now includes a responsive proof-path visual, an
evidence-coverage donut, and deterministic policy-drift/blocked-gate bars.
These are direct bounded-graph facts, not an AI score or a productivity claim.
The existing action controls and authority locks remain explicit.

## Commercial boundary

The new local dossier is free. The future GitHub Assurance Seat remains free
through December 1, 2026, with a scheduled $5.95 USD per named seat per month
offer from December 2, 2026. Checkout, entitlement, and enforcement are not
live. The separate JetBrains pricing plan remains subject to its own approval
and activation gates.

## Install

```powershell
pip install factoryline-code-factory==0.34.0
factory github assurance-dossier --help
factory graph ops --root . --json
```

Time, token, cost, and productivity results remain unavailable unless exact
paired observations are supplied. A receipt proves only declared checks and
the supplied environment.
