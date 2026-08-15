# ProofSearch: Verified Counterfactual Repair

ProofSearch answers a question ordinary agent loops leave unresolved:

> Of the repairs that look plausible, which is the smallest candidate whose
> supplied receipt evidence supports it?

It uses Graph Forensics to start at the first semantic divergence, Graph Impact
to derive the minimum affected proof slice, and supplied local receipts to
reject or rank candidates. It never generates or applies a patch.

## Two-phase workflow

```powershell
factory proofsearch plan `
  --root . `
  --baseline .factory/graph-runs/baseline.lineage.json `
  --candidate .factory/graph-runs/failed.lineage.json `
  --changed src/service.py `
  --changed tests/test_service.py `
  --out .factory/proofsearch/repair.plan.json `
  --json

factory proofsearch evaluate .factory/proofsearch/candidates.json `
  --root . `
  --out .factory/proofsearch/repair.evaluation.json `
  --json

factory proofsearch verify .factory/proofsearch/repair.evaluation.json `
  --root . --json
```

The request schema is `factory.proofsearch-request.v1`. Each candidate binds:

- one local patch file and SHA-256 digest;
- its exact changed paths;
- 1 through 64 required or optional JSON proof receipts, their hashes, and a
  pass/fail outcome that must agree with the declared status;
- exact mutation killed/total counts;
- declared test-weakening, error-suppression, and scope-expansion guardrails;
- risk score and changed-line count; and
- measured proof time, with tokens and cost left null when unavailable.

ProofSearch accepts 2 through 12 candidates. A candidate is ineligible when a
required proof fails, a receipt changes, its outcome is absent or contradicts
the declared status, a mutant survives, its paths exceed
the sealed plan, or an unsafe guardrail is declared. Eligible candidates are
ordered by risk, changed lines, proof time, measured tokens, measured cost, and
stable candidate identifier. Failed proof always loses before efficiency is
considered.

## Graph Ops Counterfactual Arena

Graph Ops displays every candidate, exact rejection reasons, proof runtime,
mutation result, changed scope, measured or unavailable token/cost values, the
winner rationale, and the sealed evaluation hash. Users can:

- copy the read-only verification command;
- export the displayed decision JSON;
- validate winner and authority guardrails; and
- see that apply, merge, publish, and deployment remain locked.

## Measurement boundary

ProofSearch reports time, token, or cost savings only when the request includes
an exact paired baseline. Productivity remains null unless a separate measured
workflow provides it. Candidate counts, commands, changed lines, and proof
reuse are not silently converted into productivity claims.

## Authority boundary

ProofSearch does not invoke a model, execute candidate commands, create or
remove worktrees, change tests, apply patches, commit, approve, merge, publish,
deploy, sign, message, access credentials, or grant connectors. External agent
runners may prepare candidates, but their outputs enter ProofSearch as
untrusted local evidence.
