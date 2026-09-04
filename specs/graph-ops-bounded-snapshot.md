# Spec: Graph Ops bounded snapshot
## MUST - Functional core
### Requirements (EARS)
- When `REQ_GRAPH` builds a Graph Ops snapshot, it shall preserve the exact read-only nodes, edges, facts, markers, recommendations, projections and hashes produced for the same workspace state.
- When `REQ_BOUND` evaluates Graph Ops architecture, it shall return pass only when `graph_ops_snapshot` is at or below 210 source lines and cyclomatic complexity 10 without raising either threshold.
- When `REQ_AUTHORITY` builds a Graph Ops snapshot, it shall return read-only evidence without invoking subprocess, network, publication, deployment, signing, credential or provider operations.
### Acceptance criteria
```gherkin
Scenario: Snapshot behavior
 Given REQ_GRAPH reads a workspace fixture
 When REQ_GRAPH builds its snapshot
 Then REQ_GRAPH returns the tested nodes facts markers projections and hashes
Scenario: Bounded coordinator
 Given REQ_BOUND inspects graph_ops_snapshot
 When REQ_BOUND runs architecture review
 Then REQ_BOUND passes 210 lines and complexity 10
Scenario: Read only
 Given REQ_AUTHORITY reads a workspace fixture
 When REQ_AUTHORITY builds its snapshot
 Then REQ_AUTHORITY leaves all workspace files unchanged
```
## SHOULD - Structural
- Extract collection, fact mapping and marker mapping into deterministic private helpers. Preserve sorted order and the base graph hash boundary before admission packets. No public function signature or receipt schema changes.
