# Spec: forgeline-intent-receipt-lineage-edge-v1

Status: proposed
SpecFactor-target: 0.75-2.5

## MUST — make verified Forge lineage traversable

### Requirements (EARS)

- When `REQ_INTENT_LINEAGE_EDGE` sees a valid, hash-bound Factoryline intent adapter, Graph Ops shall emit exactly one `intent_source` node for the normalized Forge ship source and one `bound_to_forge_line` edge from the adapter node to that source node.
- If `REQ_INTENT_LINEAGE_EDGE_FAIL_CLOSED` sees a missing, malformed, invalid, or mismatched Forge binding, Graph Ops shall emit no `intent_source` node and no lineage edge, while preserving the existing untraceable or blocked status.
- When `REQ_INTENT_LINEAGE_EDGE_FACTS` emits a source node, its path, 1-based line, raw-line SHA-256, source type, and false authority flags shall match the verified binding; the edge shall remain navigation evidence and shall not grant authority.
- When `REQ_INTENT_LINEAGE_EDGE_UI` renders the graph, the read-only lanes shall expose the intent trace and source node without adding an execution, repair, approval, publication, deployment, signing, messaging, credential, or connector control.

### Acceptance criteria

```gherkin
Scenario: connect a bound adapter to its exact Forge line
  Given `REQ_INTENT_LINEAGE_EDGE` sees a valid Factoryline adapter bound to a readable Forge ship line
  When Graph Ops builds its snapshot
  Then exactly one intent_source node has the verified source, line, and raw-line hash
  And one bound_to_forge_line edge connects the intent trace to that node

Scenario: fail closed when the binding is not trustworthy
  Given `REQ_INTENT_LINEAGE_EDGE_FAIL_CLOSED` sees a missing, malformed, invalid, or mismatched Forge binding
  When Graph Ops builds its snapshot
  Then no intent_source node or lineage edge is emitted
  And the intent trace remains untraceable or blocked

Scenario: preserve evidence and authority boundaries
  Given `REQ_INTENT_LINEAGE_EDGE_FACTS` emits a bound source node
  When a reviewer inspects the node and edge
  Then the source path, line, raw-line hash, and false authority flags are present
  And execution, approval, publication, deployment, signing, messaging, credential, and connector authority remain false

Scenario: render graph navigation without controls
  Given `REQ_INTENT_LINEAGE_EDGE_UI` renders a bound adapter in Graph Ops
  When the graph lanes are displayed
  Then intent_trace and intent_source are visible as read-only node lanes
  And no execution, repair, approval, publication, deployment, signing, messaging, credential, or connector control is added
```

## SHOULD — boundaries

- Read only the bounded local Factoryline adapter and Forge receipt source; do not rewrite either source or follow links outside the workspace.
- Emit a single stable source node and edge per verified adapter projection; preserve graph bounds and deduplication.
- Treat the node and edge as reviewer navigation evidence, never as a signature, production-readiness claim, approval, release authorization, or execution permission.
