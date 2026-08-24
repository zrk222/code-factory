# ADR: Graph Ops unification v1

## Decision

Add a deterministic, read-only `factory.graph-ops.v1` overlay that compiles
existing local Product Graph, value-slice, mission, approval, completion,
content-addressed proof, proof-plan, trace, receipt, and artifact facts. Serve
it through `factory graph ops` and Factory Studio's authenticated
`GET /api/graph-ops`, with a separate accessible Graph Ops visual page.

## Context

The product already has several evidence graphs, each optimized for a distinct
decision. Users had to reconstruct the overall path from separate CLI commands
and dashboard panels. Replacing those stores with a generic graph engine would
weaken their verification boundaries and risk treating a framework checkpoint
as authority.

## Consequences

- The overlay has no write, execution, approval, promotion, credential, or
  connector authority.
- A valid completion receipt is the sole source for requirement evidence.
- Graph results are canonical, bounded, path-contained, and partial on errors.
- LangGraph remains optional interoperability around the guarded mission state
  machine; it is not evidence or release authority.
- Optimization means the deterministic smallest next action from declared facts,
  not a performance, cost, or token-savings claim.
