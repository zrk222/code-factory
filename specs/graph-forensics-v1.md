# Spec: graph-forensics-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core
### Description
Graph Forensics gives local developers and delivery teams a deterministic explanation of where two graph runs first diverged, how changed state propagated, which concurrency anomalies are present, and which non-executing recovery branch requires review.

### User roles
- Graph operator supplying local lineage or native mission-ledger evidence.
- Human reviewer deciding whether a proposed checkpoint fork may execute.

### Requirements (EARS)
- The system shall return `GRAPH_LINEAGE_VERIFIED` for a `factory.graph-lineage.v1` receipt containing 1 through 2000 contiguous steps and return `GRAPH_LINEAGE_INVALID` for a mismatched canonical SHA-256 digest.
- When two verified receipts share one graph identifier, the system shall return `GRAPH_FORENSICS_FIRST_DIVERGENCE` with the first semantic divergence, downstream causal nodes, deterministic anomalies, and one recovery preview without executing a graph, and the system shall return `GRAPH_LINEAGE_GRAPH_MISMATCH` when the graph identifiers differ.
- If parallel writers do not declare one common reducer, the system shall return `PARALLEL_WRITE_CONFLICT` for the affected state key.
- If a read or write references an older recorded state version, the system shall return `STALE_READ` or `STALE_WRITE` with observed and latest versions.
- If one completed effect appears more than once, the system shall return `DUPLICATE_SIDE_EFFECT` and identify its first sequence.
- When a native mission event chain is supplied, the system shall return `GRAPH_LINEAGE_MISSION_LEDGER_EXPORTED` after verifying the native mission event chain through the existing mission ledger and exporting the native mission event chain control-state transitions as sealed lineage.
- The system shall return `GRAPH_FORENSICS_AUTHORITY_RETAINED` and `false` for execution, checkpoint mutation, approval, publication, deployment, signing, messaging, credential, and connector authority in every forensic result.
- The system shall return `GRAPH_LINEAGE_BOUNDS_ENFORCED` when bounding each source to 2097152 bytes, each lineage to 2000 steps, and each state list to 400 objects.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: A candidate run diverges from a verified baseline
  Given two hash-sealed lineage receipts with the same graph_id and a changed candidate state at sequence 2
  When the operator runs factory graph forensics
  Then the result identifies sequence 2, returns its downstream causal nodes, and sets recovery_plan.execute to false

Scenario: A lineage receipt is tampered after sealing
  Given one lineage receipt whose decision no longer matches lineage_sha256
  When the operator runs factory graph lineage-verify
  Then the command exits nonzero and reports lineage_sha256 does not match canonical lineage content

Scenario: Parallel writes lack one reducer
  Given two nodes write the same state key in one superstep using replace mode
  When the candidate lineage is analyzed
  Then the anomalies contain PARALLEL_WRITE_CONFLICT for that key

Scenario: The maximum lineage remains bounded
  Given a factory.graph-lineage.v1 receipt containing 2000 contiguous steps and one canonical SHA-256 digest
  When the operator runs factory graph lineage-verify
  Then the verifier returns GRAPH_LINEAGE_VERIFIED for 2000 steps and GRAPH_LINEAGE_INVALID for 2001 steps

Scenario: Semantic divergence includes anomalies and recovery
  Given two verified receipts with one graph_id and different semantic fingerprints
  When the operator runs factory graph forensics
  Then the result returns GRAPH_FORENSICS_FIRST_DIVERGENCE with the first semantic divergence, downstream causal nodes, deterministic anomalies, and one recovery preview without graph execution

Scenario: Semantic comparison rejects different graph identifiers
  Given two verified receipts with different graph_id values
  When the operator runs factory graph forensics
  Then the command returns GRAPH_LINEAGE_GRAPH_MISMATCH without GRAPH_FORENSICS_FIRST_DIVERGENCE

Scenario: A state read or write is stale
  Given one read or write references a version lower than the latest recorded version
  When the candidate lineage is analyzed
  Then the result returns STALE_READ or STALE_WRITE with observed_version and latest_version

Scenario: A completed effect repeats
  Given one effect_id has completed at two different sequences
  When the candidate lineage is analyzed
  Then the result returns DUPLICATE_SIDE_EFFECT and first_sequence

Scenario: Native mission lineage uses the verified ledger
  Given a native mission event chain with a valid event hash chain and bound receipts
  When the operator runs factory graph lineage-mission
  Then the command returns GRAPH_LINEAGE_MISSION_LEDGER_EXPORTED after verifying the native mission event chain and exporting sealed control-state lineage

Scenario: Forensics retains every authority boundary
  Given a valid graph forensic comparison
  When the forensic result is returned
  Then the result returns GRAPH_FORENSICS_AUTHORITY_RETAINED and execution, checkpoint_mutation, approval, publication, deployment, signing, messaging, credential, and connector authority are false

Scenario: Source and state collections exceed their bounds
  Given a source larger than 2097152 bytes or a state list containing 401 objects
  When lineage verification runs
  Then the verifier returns GRAPH_LINEAGE_BOUNDS_ENFORCED and rejects the source or state list before forensic comparison
```

## SHOULD - Technical and structural
- ADR references: docs/GRAPH_FORENSICS.md and docs/GRAPH_OPS.md
- Data model: hash-only state reads and writes with explicit monotonically increasing versions
- API contract: `verify_graph_lineage`, `seal_graph_lineage`, `seal_mission_graph_lineage`, and `graph_forensics`

## SHOULD NOT - Implementation details
- The feature should not execute a graph, mutate a checkpoint, repeat a side effect, infer hidden model state, or claim unmeasured savings.

## Decision logic (factory candidates)
This feature has no HSF business-decision candidate. The deterministic
controller rejects invalid lineage or mismatched graph identifiers, returns the
first differing semantic fingerprint and causal cone, returns
`no_recovery_required` when every fingerprint matches, and reports
`PARALLEL_WRITE_CONFLICT` when same-superstep writers lack one common reducer.
