# Code Factory 0.33.0

## Evidence Frontier: choose the next fact to collect

Evidence Frontier is a deterministic, local Graph Ops planning layer. It does
not execute an experiment or repair a workspace. Instead, it answers one
bounded question:

> Which supplied experiment distinguishes the greatest number of viable repair pairs?

- `factory proofsearch frontier plan` binds a verified current ProofSearch
  evaluation and 1 through 64 supplied experiment hypotheses.
- Each hypothesis declares `pass`, `fail`, or `unknown` predictions for every
  eligible repair candidate. Those predictions are unverified until an
  independent, separately approved runner produces external evidence.
- The selector counts only pairs with different non-unknown predictions. Ties
  use a bound historical elapsed-time observation, then the experiment ID.
- `factory proofsearch frontier verify` detects alteration of the frontier or
  its bound ProofSearch evaluation.
- A zero-separation input returns `EVIDENCE_FRONTIER_NO_DISCRIMINATING_EXPERIMENT`
  rather than inventing another test.

## Graph Ops control surface

The Unified Graph Ops UI now presents an Evidence Frontier panel, ranked typed
nodes, a decision hash, and copy/export/validate controls. The **Run next
experiment** control is intentionally disabled.

Evidence Frontier cannot execute commands, mutate a workspace or checkpoint,
approve, merge, publish, deploy, sign, send messages, access credentials, or
grant connectors. It makes the next proof question inspectable; it does not
make an autonomous delivery decision.

## Release media and public surfaces

The release includes a current 1280 × 800 captured Graph Ops Evidence Frontier
surface in the repository visual policy, Product Hunt gallery kit, Hugging Face
preview, and release bundle.

## Install

```powershell
pip install factoryline-code-factory==0.33.0
factory proofsearch frontier --help
factory graph ops --root . --json
```

Time, token, cost, and productivity results remain unavailable unless Code
Factory is given exact paired observations. A sealed receipt proves only the
declared checks and supplied environment.
