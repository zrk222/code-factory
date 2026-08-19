# Developer Memory Brief

`factory memory brief` turns the current local change set into a compact,
read-only explanation of the next safe proof action.

```powershell
factory memory brief --root . --json
factory memory brief --root . --base origin/main --changed src\checkout.py --json
```

## What it shows

- exact changed paths when Git or explicit `--changed` inputs are available;
- declared proof inputs that no longer match, stale proofs, coverage gaps, and
  the policy-selected rerun plan;
- one capped list of actions, each with **what changed**, **why it matters**,
  **what to do next**, and its bound evidence hash;
- redacted Factory Continuity counts and record IDs only; and
- observed local Git contributor cards and aggregate contribution counts for
  the selected path set.

Factory Studio and Graph Ops render the same brief with manual refresh controls
and a five-second local auto-refresh interval while the page remains open.

## What it deliberately does not do

The brief does not run a test, execute a proof, recall continuity bodies, write
a memory record, approve work, modify code, call a model, publish, deploy, or
access credentials. Observed Git contributors are not a verified identity
directory, billing-seat roster, approval record, ownership assignment, or
productivity measure.

When the changed-path set cannot be determined, the brief returns one explicit
blocking action instead of inventing a proof recommendation.
