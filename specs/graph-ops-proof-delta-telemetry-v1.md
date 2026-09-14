# Spec: graph-ops-proof-delta-telemetry-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Graph Ops shall project each verified local Proof-Delta receipt into a
deterministic, read-only telemetry record and a typed graph lineage. A halted
retry is surfaced as `NO_GAIN_HALT` with exact candidate/evidence bindings,
proof debt, and one fact-derived next action. The projection must not execute,
retry, mutate, approve, or publish work.

### User roles

- Developer inspecting why an agent retry stopped.
- Coding agent consuming a bounded Graph Ops fact without authority.
- Human reviewer deciding whether a new candidate and evidence are warranted.

### Declared facts

- `verified_delta`: the source receipt passed `verify_proof_delta`.
- `halt_classified`: a non-eligible verified delta is labelled `NO_GAIN_HALT`.
- `candidate_hash_bound`: telemetry carries the repair and prior candidate diff hashes.
- `evidence_digest_bound`: telemetry carries a SHA-256 digest of repair and new evidence references.
- `proof_debt_present`: a halted retry lists the unresolved criterion and evidence debt.
- `next_action_present`: each telemetry record provides one bounded next action.
- `authority_none`: all execution, approval, publication, deployment, signing, credential, connector, and messaging flags remain false.
- `graph_edges_bound`: guard, candidate, evidence, blocker, debt, and next-action nodes are linked by typed edges.

### Requirements (EARS)

- When `REQ_GRAPH_DELTA_TELEMETRY` receives a verified Proof-Delta receipt, it shall emit `factory.graph-ops.proof-delta-telemetry.v1` with a stable telemetry hash, candidate/evidence digests, `authority_none`, and a matching `proof_delta_guard` node without writing workspace files. [R1]
- When `REQ_GRAPH_NO_GAIN_HALT` receives a verified non-eligible receipt, it shall classify the record as `NO_GAIN_HALT`, set blocker type `STALE_EVIDENCE_OR_UNCHANGED_CANDIDATE`, preserve candidate/evidence change flags, list proof debt, and provide the bounded next action `supply_modified_candidate_and_fresh_evidence`. [R2]
- When `REQ_GRAPH_LINEAGE` projects telemetry, it shall link the proof-delta node to guard, candidate, evidence, blocker, debt, and next-action nodes with typed edges, while retaining false authority and execution flags. [R3]

### Acceptance criteria

```gherkin
Scenario: A no-gain retry is visible without executing it
  Given REQ_GRAPH_NO_GAIN_HALT and a verified Proof-Delta with no new evidence
  When Graph Ops projects the workspace
  Then the telemetry status is NO_GAIN_HALT, the blocker and proof debt are present, and authority execution is false

Scenario: Candidate and evidence bindings are reproducible
  Given REQ_GRAPH_DELTA_TELEMETRY and one verified receipt
  When Graph Ops projects the same workspace twice
  Then telemetry hashes, candidate hashes, evidence digests, and graph edges match exactly

Scenario: Halt lineage is inspectable
  Given REQ_GRAPH_LINEAGE and a NO_GAIN_HALT telemetry record
  When the graph and Mermaid projection are read
  Then guard, blocker, candidate, evidence, debt, and next-action nodes are connected by typed edges
```

## SHOULD - Technical and structural

- API: `graph_ops_snapshot(root)` returns `proof_delta_telemetry` and typed nodes/edges.
- Telemetry is derived only from `verify_proof_delta`; no raw prompts, credentials, or provider state are imported.
- Mermaid remains a bounded rendering of the same deterministic graph.

## SHOULD NOT - Non-goals

- Do not start or retry a worker, run a verifier, apply a repair, or alter a Proof-Delta receipt.
- Do not infer that a telemetry record is a release approval or production certificate.
- Do not add network transport, subscriptions, hosted state, or provider integrations.

## Decision logic

| # | if | then |
|---|---|---|
| 1 | `verified_delta` is false | omit telemetry and preserve the existing source error |
| 2 | `verified_delta` and `halt_classified` are true | emit `NO_GAIN_HALT` telemetry, blocker, debt, action, and lineage edges |
| 3 | `verified_delta` is true and `halt_classified` is false | emit `REPAIR_ADMITTED` telemetry with the same authority-free lineage |
| 4 | `authority_none` or `graph_edges_bound` is false | mark the Graph Ops snapshot incomplete and retain the review recommendation |
