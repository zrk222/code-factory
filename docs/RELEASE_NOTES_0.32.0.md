# Code Factory 0.32.0

## ProofSearch: verified counterfactual repair

Code Factory can now explain where two graph runs diverged and determine which
of several supplied repairs is the smallest candidate that actually carries
complete evidence.

- `factory proofsearch plan` seals the first semantic divergence, approved
  changed paths, and exact Graph Impact proof slice.
- `factory proofsearch evaluate` verifies 2 through 12 patch and proof hashes,
  required gate outcomes, mutation killed/total results, scope, test weakening,
  error suppression, risk, changed lines, runtime, and available token/cost
  observations.
- `factory proofsearch verify` detects evaluation or evidence tampering.
- Failed proof, surviving mutants, and unsafe scope always lose before an
  efficiency metric is considered.
- The result explains every rejection and Pareto-dominated candidate.

## Graph Ops becomes the repair control plane

The new Counterfactual Arena shows all repair candidates, the exact winner
rationale, proof runtime, mutation results, risk, changed scope, measured or
unavailable savings, and the sealed evaluation hash. Reviewers can copy the
verification command, export the decision, and validate guardrails in one UI.

Apply, test mutation, checkpoint mutation, approval, merge, publication,
deployment, signing, messaging, credentials, and connectors remain locked.

The Graph Ops surface was refined with the Prestige design skill. The current
receipt is 92/100 PASS, with zero P1/P2 critique findings and 3/3 design
challenge mutants killed. The maintainer's observation is that Prestige
materially improved hierarchy, clarity, and polish; that observation is not a
measured conversion claim.

## Also included

This release includes Graph Forensics: sealed semantic lineage, first-divergence
and causal-cone analysis, stale-read/write, parallel-write, and duplicate-effect
findings, plus a non-executing recovery preview.

## Install

```powershell
pip install factoryline-code-factory==0.32.0
factory graph ops --root . --json
```

Savings are reported only from exact paired observations. No percentage or
productivity claim is inferred from candidate counts, commands, or proof reuse.
