# Spec: graph-ops-visual-v1

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Code Factory shall compile existing local Product Graph, value-slice, mission,
approval, completion, content-addressed proof, proof-plan, and trace artifacts
into one deterministic, read-only Graph Ops result. The local Factory Studio
shall give users an accessible visual view of that result so they can follow
requirements through execution and evidence, see unknown or stale state, and
identify one safe next action. The graph is an inspection and planning surface;
it must never execute a gate, approve work, publish, deploy, sign, message, or
access credentials.

### User roles

- Local developer inspecting the exact proof path after a change.
- Mission owner deciding whether a bounded action is ready for human approval.
- Reviewer tracing a requirement through its slice, mission, and evidence.
- Coding agent consuming a compact, deterministic result rather than raw logs.

### Requirements (EARS)

- The system shall return schema `factory.graph-ops.v1` with marker `GRAPH_OPS_UNIFIED_READ_ONLY` and a SHA-256 over a canonically ordered graph result. [R1]
- The system shall emit marker `GRAPH_OPS_TYPED_LOCAL_NODES` with typed nodes only for readable local artifacts beneath the selected workspace root, using node kinds `product`, `requirement`, `slice`, `mission`, `approval`, `completion`, `proof`, `gate`, `trace`, `receipt`, and `artifact`. [R2]
- When a Product Graph and value-slice plan are present, the system shall return marker `GRAPH_OPS_SLICE_LINKS_EXACT` with a graph where every declared requirement has exactly 1 `assigned_to` edge to a listed slice and every declared slice dependency has 1 `depends_on` edge. [R3]
- When a mission references a listed slice, the system shall return marker `GRAPH_OPS_MISSION_EVIDENCE_LINKED` with a graph containing 1 `governs` edge from that slice to the mission; when a valid completion receipt exists, the graph shall contain 1 `verifies` edge from the completion to every requirement in the mission slice. [R4]
- When a content-addressed proof receipt is present, the system shall return marker `GRAPH_OPS_PROOF_HASH_STATUS` after verifying its current hashes and showing it as `verified` or `stale`; inputs and outputs shall be represented as artifact edges. [R5]
- When a proof plan, trace, or trace receipt is present, the system shall return marker `GRAPH_OPS_DECLARED_GATE_STATE` with its declared RUN, REUSE, SKIP, BLOCK, stage, or verification state without executing its command. [R6]
- If an artifact is malformed, unreadable, larger than 1,048,576 bytes, outside the workspace, or would exceed 500 nodes or 1,000 edges, the system shall return marker `GRAPH_OPS_PARTIAL_RESULT` with all earlier readable nodes plus at least 1 compact source error and `complete:false`. [R7]
- The system shall return marker `GRAPH_OPS_RECOMMENDATION_EXACT` with exactly one optimized-result recommendation derived only from graph facts: `initialize_graph`, `rerun_invalid_proof`, `resolve_blocked_gate`, `run_required_validation`, `collect_completion_evidence`, `review_verified_graph`, or `review_external_runtime_failure`. [R8]
- The system shall return marker `GRAPH_OPS_AUTHORITY_RETAINED` and explicit false values for execution, approval, publication, deployment, signing, messaging, credential, and connector authority. [R9]
- When `factory graph ops --root ROOT --json` is invoked, the system shall print marker `GRAPH_OPS_CLI_READ_ONLY` with the Graph Ops result and perform zero writes under ROOT. [R10]
- When Factory Studio receives an authenticated `GET /api/graph-ops` request, it shall return marker `GRAPH_OPS_STUDIO_AUTHENTICATED` with the same read-only graph result; an unauthenticated request shall return HTTP 403. [R11]
- The system shall return marker `GRAPH_OPS_VISUAL_ACCESSIBLE` with a Factory Studio Graph Ops page containing graph totals, the one fact-derived next action, an accessible node-lane visualization, a selected-node detail view, an explicit empty state, and a read-only authority notice at viewport widths of 768 pixels or less. [R12]
- The system shall return marker `GRAPH_OPS_TEXT_NODE_RENDERING` with a Graph Ops page whose dynamic labels use text nodes rather than HTML insertion and whose only dynamic request is to the loopback Studio graph endpoint with the existing session token. [R13]
- When `factory mvp OUTCOME --root ROOT --json` is invoked, the system shall create exactly one local web MVP starter at `ROOT/my-mvp` with marker `MVP_STARTER_CONTAINED`, no external-effect authority, and explicit next proof commands. [R14]
- When a user opens Factory Studio without a mode query, the system shall return marker `FACTORY_DUAL_TRACK_START` and show an `Instant MVP` path for outcome-first local starters plus a `Professional workflow` path to Graph Ops, Product Missions, proof reuse, policy, and enterprise controls. [R15]
- When `factory graph impact --root ROOT --changed PATH --json` is invoked, the system shall return marker `GRAPH_OPS_IMPACT_EXACT` with only proofs and declared gates linked to declared changed-path value `PATH` by an explicit input-artifact edge, a distinct labelled verified-current set, and a rerun set containing only stale matched proofs. [R16]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Follow a completed requirement through the unified graph
  Given a Product Graph with one value slice and a completed mission
  When Graph Ops compiles the local artifacts
  Then the requirement, slice, mission, and completion nodes are linked
  And the requirement is counted as evidenced only when the completion verifies
  And the response schema is `factory.graph-ops.v1`

Scenario: Show stale proof without running it
  Given a recorded read-only proof whose declared input has changed
  When Graph Ops compiles the local artifacts
  Then that proof has status stale
  And the recommendation is rerun_invalid_proof
  And no command is executed

Scenario: Use the visual Graph Ops surface safely
  Given a Factory Studio session token
  When the user opens the Graph Ops view
  Then the page renders graph totals, lanes, detail, and the authority notice
  And its graph request uses the local authenticated endpoint
  And no publish, deploy, sign, credential, connector, or message action is available

Scenario: Inspect Graph Ops through the bounded local interfaces
  Given a workspace root `ROOT`
  When `factory graph ops --root ROOT --json` is invoked
  Then the command prints `GRAPH_OPS_CLI_READ_ONLY` and writes zero files under ROOT
  When an authenticated `GET /api/graph-ops` request is received
  Then the endpoint returns `GRAPH_OPS_STUDIO_AUTHENTICATED`
  And an unauthenticated `GET /api/graph-ops` request returns HTTP 403

Scenario: Keep unknowns honest
  Given no local Factory graph artifacts
  When Graph Ops compiles the workspace
  Then the graph has zero nodes
  And the recommendation is initialize_graph
  And the page explains that no evidence path exists yet

Scenario: Start an MVP before learning the factory vocabulary
  Given an empty workspace root `ROOT`
  When `factory mvp OUTCOME --root ROOT --json` is invoked
  Then `MVP_STARTER_CONTAINED` is returned with one local web target at `ROOT/my-mvp`
  And its next proof commands are explicit
  And no deploy, publish, credential, connector, or message action is available

Scenario: Choose a user level without changing the underlying proof boundary
  Given a new Factory Studio session
  When Factory Studio opens without a mode query
  Then `FACTORY_DUAL_TRACK_START` is present with `Instant MVP` and `Professional workflow`
  And the professional path includes `GRAPH_OPS_UNIFIED_READ_ONLY`

Scenario: Analyze a change without broad reruns
  Given a proof receipt with an explicit input artifact `PATH`
  When `factory graph impact --root ROOT --changed PATH --json` is invoked
  Then `GRAPH_OPS_IMPACT_EXACT` returns only the matched input-linked proof and gate nodes
  And only a stale matched proof appears in the rerun set
  And no validation command is executed

Scenario: Every Graph Ops requirement has an observable marker
  Given the Graph Ops contract
  When strict validator mutation runs
  Then markers include `GRAPH_OPS_UNIFIED_READ_ONLY`, `GRAPH_OPS_TYPED_LOCAL_NODES`, `GRAPH_OPS_SLICE_LINKS_EXACT`, `GRAPH_OPS_MISSION_EVIDENCE_LINKED`, `GRAPH_OPS_PROOF_HASH_STATUS`, `GRAPH_OPS_DECLARED_GATE_STATE`, `GRAPH_OPS_PARTIAL_RESULT`, `GRAPH_OPS_RECOMMENDATION_EXACT`, `GRAPH_OPS_AUTHORITY_RETAINED`, `GRAPH_OPS_CLI_READ_ONLY`, `GRAPH_OPS_STUDIO_AUTHENTICATED`, `GRAPH_OPS_VISUAL_ACCESSIBLE`, `GRAPH_OPS_TEXT_NODE_RENDERING`, `MVP_STARTER_CONTAINED`, `FACTORY_DUAL_TRACK_START`, and `GRAPH_OPS_IMPACT_EXACT`
```

## SHOULD - Technical/structural

- ADR reference: `adr/graph-ops-unification-v1.md`.
- Data model: GraphOpsFacts(node_count, stale_proof_count, blocked_gate_count, run_gate_count, unevidenced_requirement_count).
- Result schema: the R1 schema value with canonically sorted nodes and edges.
- API contract: the R10 local CLI invocation and the R11 authenticated Studio endpoint.
- Use the existing local artifact formats and existing proof/trace verification;
  do not introduce a database or a model dependency.
- Keep the graph bounded to at most 500 nodes and 1,000 edges per snapshot.
- Use UTF-8 canonical JSON with sorted keys and compact separators. Artifact and
  receipt node identifiers may expose the first 24 SHA-256 characters; a
  receipt label may expose its first 12 characters. The Mermaid projection may
  show at most 80 nodes and 80 label characters. The visual lane may render
  its first 40 typed nodes and report the remainder as text.

## SHOULD NOT - Implementation details

- Do not replace the Product Mission SQLite event chain, Proof Trace, or
  Assurance graph with a new authority source.
- Do not use LangGraph as an evidence or release authority.
- Do not infer requirement coverage from labels, file names, or a successful
  build; only a valid mission completion binds completion evidence.
- Do not report performance, cost, or token savings unless an existing receipt
  already supplies a measured value.
- Do not add a third-party runtime dependency.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `node_count` is 0 | return `initialize_graph` |
| 2 | `stale_proof_count` is greater than 0 | return `rerun_invalid_proof` |
| 3 | `blocked_gate_count` is greater than 0 | return `resolve_blocked_gate` |
| 4 | `run_gate_count` is greater than 0 | return `run_required_validation` |
| 5 | `unevidenced_requirement_count` is greater than 0 | return `collect_completion_evidence` |
| 6 | otherwise | return `review_verified_graph` |
