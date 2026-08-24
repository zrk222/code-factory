# Code Factory 0.39.0

## LangGraph resume evidence, without runtime authority

Code Factory 0.39 adds the **LangGraph Assurance Bridge**: a free, local-first
way to compare a normal graph path with a separately recorded resume path
before a reviewer accepts the result.

- A team-owned test harness records only SHA-256 state, decision, and
  side-effect identifiers, then seals each transition lineage.
- `factory langgraph replay-verify` reports deterministic resume parity only
  when supplied sealed lineages match and neither reveals a duplicate completed
  effect, stale read/write, or unsafe parallel write.
- A mismatch produces a shareable `LANGGRAPH_INCIDENT_CAPSULE` with receipt
  hashes, the first divergent node, state-key identifiers, a Mermaid map, and
  a review-only causal recovery cone. It never stores raw state values, prompt
  text, or source secrets.
- The same read-only comparison is available to an MCP-capable coding
  assistant through `factory.langgraph_assurance`, and an opt-in GitHub Action
  writes a pull-request job-summary Proof Card from already-recorded receipts.

## Use it with a LangGraph agent flow

Run the graph in **your own** test harness once for the intended reference path
and once through a forced resume or interrupted path. Seal both receipts, then:

```powershell
factory langgraph replay-verify `
  --root . `
  --reference .factory/langgraph/reference.json `
  --resumed .factory/langgraph/resumed.json `
  --out .factory/langgraph/assurance.json `
  --json
```

Use the result as a review gate alongside your existing LangGraph tests and
checkpoint configuration. A `VERIFIED` result covers only the supplied sealed
transitions; a divergence exits non-zero after writing its incident capsule.

## Install

```powershell
pip install factoryline-code-factory==0.39.0
factory langgraph replay-verify --help
```

Read the complete [LangGraph Assurance guide](LANGGRAPH_ASSURANCE.md) for the
small recorder adapter, MCP call, and GitHub Action example.

## Boundary

This release does not import or invoke LangGraph, mutate a checkpoint, replay a
side effect, repair source, approve a pull request, merge, deploy, publish,
sign, access credentials, or send a message. It does not establish production
resilience or calculate time, token, cost, quality, or productivity savings.
