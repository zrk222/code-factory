# Spec: langgraph-assurance-bridge
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Give teams using LangGraph a deterministic, local proof surface for the failure
mode that ordinary graph checkpoints do not prove: whether a resumed execution
preserves the observed semantic state transitions and idempotency-bound side
effects of a reference execution.  The bridge must operate without importing
or invoking LangGraph, so it remains a small, optional adapter around a
team-owned test harness rather than a competing orchestrator.

### User roles
- Senior developer: adds a hash-only transition recorder around a LangGraph
  test harness and needs a fast, reviewable explanation for a resume mismatch.
- Team reviewer: needs an independently repeatable receipt that identifies the
  first divergent node, affected state keys, and a smallest human-approved
  recovery cone.
- Agent author: needs a local MCP-readable status without granting graph,
  checkpoint, side-effect, approval, or release authority.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- The system shall return `LANGGRAPH_TRANSITION_HASH_ONLY` and sealed contiguous `factory.graph-lineage.v1` steps for supplied JSON-serializable before/after state without storing raw values.
- When two verified same-graph lineages are semantically equal and contain no deterministic anomaly, the system shall return `LANGGRAPH_RESUME_PARITY_VERIFIED`, `no_recovery_required`, and no quality, time, token, cost, or productivity estimate.
- When two verified same-graph lineages differ or the resumed lineage contains `DUPLICATE_SIDE_EFFECT`, `STALE_READ`, `STALE_WRITE`, or `PARALLEL_WRITE_CONFLICT`, the system shall return `LANGGRAPH_REPLAY_DIVERGENCE` with the first divergent node and deterministic causal cone.
- When a replay divergence is reported, the system shall return `LANGGRAPH_INCIDENT_CAPSULE` with deterministic Mermaid, lineage hashes, node identifiers, and state-key identifiers, without raw state values, prompts, secrets, or inferred savings.
- If a supplied state value is not canonical JSON, a lineage is invalid, graph identifiers differ, or an output escapes the workspace, the system shall return `LANGGRAPH_INPUT_REJECTED` before writing a receipt.
- Where an MCP client requests a bridge result, the system shall return `LANGGRAPH_MCP_READ_ONLY` and `false` for graph invocation, checkpoint mutation, side-effect replay, approval, deployment, publication, credential, and connector authority.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: resume parity holds
  Given a recorder has sealed a reference lineage and a resumed lineage with
  identical state-transition hashes
  When the bridge verifies resume parity
  Then it returns LANGGRAPH_RESUME_PARITY_VERIFIED with no recovery action and no inferred savings

Scenario: resumed parallel reducer changes state order
  Given reference and resumed lineage receipts for the same graph differ at a
  parallel ordered-state write
  When the bridge verifies resume parity
  Then it returns LANGGRAPH_REPLAY_DIVERGENCE with the first divergent node and only the causal recovery cone, without invoking either graph
  And it returns LANGGRAPH_INCIDENT_CAPSULE without raw state values

Scenario: resumed lineage contains a deterministic anomaly
  Given a resumed lineage for the same graph contains DUPLICATE_SIDE_EFFECT, STALE_READ, STALE_WRITE, or PARALLEL_WRITE_CONFLICT
  When the bridge verifies resume parity
  Then it returns LANGGRAPH_REPLAY_DIVERGENCE with the anomaly and deterministic causal cone

Scenario: recorder rejects non-canonical state
  Given a recorder receives a state value that cannot be serialized as JSON
  When it records the transition
  Then it returns LANGGRAPH_INPUT_REJECTED and no lineage output is written

Scenario: MCP result remains read-only
  Given a local sealed parity receipt
  When an MCP client requests the bridge result
  Then it returns LANGGRAPH_MCP_READ_ONLY
  And graph invocation, checkpoint mutation, side-effect replay, approval, deployment, publication, credential, and connector authority are false

Scenario: strict bridge requirements cannot be removed
  Given the LangGraph Assurance Bridge contract
  When strict validator mutation runs
  Then markers include `LANGGRAPH_TRANSITION_HASH_ONLY`, `LANGGRAPH_RESUME_PARITY_VERIFIED`, `LANGGRAPH_REPLAY_DIVERGENCE`, `LANGGRAPH_INCIDENT_CAPSULE`, `LANGGRAPH_INPUT_REJECTED`, and `LANGGRAPH_MCP_READ_ONLY`
  And every bridge result has false graph invocation, checkpoint mutation, side-effect replay, approval, deployment, publication, credential, and connector authority
  And invalid state, invalid lineage, graph identifier mismatch, and output escape return LANGGRAPH_INPUT_REJECTED before a receipt is written
```

## SHOULD — Technical/structural
- ADR references: LangGraph supplies persistence and interruptions; Code
  Factory supplies deterministic evidence and replay-parity analysis.
- Data model: `factory.langgraph-assurance.v1` receipt wraps two existing
  `factory.graph-lineage.v1` receipts and their verification facts.
- API contract: Python `LangGraphTransitionRecorder`, CLI
  `factory langgraph replay-verify`, and MCP `factory.langgraph_assurance`.
- GitHub delivery: the existing opt-in Proof Review workflow may attach a
  supplied local assurance receipt as an advisory Proof Card. It shall not
  invoke a graph, convert the result into merge authority, or expose a
  credential-bearing GitHub App surface.
- Commercial boundary: organization policy, retention, and authenticated
  GitHub-App delivery are future service capabilities. The open bridge and
  local evidence format remain usable without a subscription.

### Bounded mechanics

- Safe graph, node, checkpoint, and state-key identifiers are 1 through 160
  ASCII-safe characters. A recorded state object contains at most 400 keys.
- Atomic receipt writes use UTF-8 JSON with `indent=2`. Transition sequence
  numbering starts at 1; output is written only after all validation succeeds.
- Mermaid node labels are capped at 100 characters. These are rendering and
  validation bounds, never workload-size, latency, token, or cost estimates.

## SHOULD NOT — Implementation details
<!-- The bridge must not import LangGraph, open a network connection, invoke a
graph, mutate checkpoints, rerun effects, or store raw state values. -->

## Decision logic (factory candidates)
This feature has no HSF business-decision candidate. The deterministic
controller rejects invalid inputs before output, returns
`LANGGRAPH_RESUME_PARITY_VERIFIED` only when the existing lineage verifier,
graph identifier equality, semantic fingerprints, and deterministic anomaly
checks all pass, and otherwise returns `LANGGRAPH_REPLAY_DIVERGENCE` with the
existing Graph Forensics causal cone. No model, runtime graph, or external
state decides the result.
