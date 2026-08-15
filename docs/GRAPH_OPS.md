# Unified Graph Ops

![Graph Ops showing sealed runs, first divergence, causal path, recovery preview, and locked Action Dock](assets/marketplace/graph-ops-forensics.png)

`factory graph ops` is a local, deterministic inspection layer over the
artifacts Code Factory already knows how to verify. It does not create a new
database, agent runtime, or authority source.

```mermaid
flowchart LR
    P["Product Graph"] --> R["Requirement"] --> S["Value slice"]
    S --> M["Mission"] --> A["Approval"]
    M --> C["Valid completion"] --> R
    P2["Read-only proof"] --> G["Declared gate state"]
    T["Proof trace"] --> X["Stage receipt"] --> F["Bound artifact"]
    R -. "only valid completion evidence" .-> C
```

## Use it

```powershell
factory graph ops --root . --json
factory graph ops --root . --mermaid
factory graph impact --root . --changed src/app.py --json
factory graph lineage-verify .factory/graph-runs/good.lineage.json --json
factory graph forensics --baseline good.lineage.json --candidate bad.lineage.json --json
factory studio --root .
```

Open `http://127.0.0.1:<port>/graph-ops` from Studio, or select **Unified
Graph Ops** from either editor integration. The page has graph totals, typed
lanes, selected-node detail, source-error visibility, an explicit empty state,
and exactly one fact-derived next action.

The JSON schema is `factory.graph-ops.v1`. Its `graph_sha256` covers canonical
ordering of the graph result. Results are bounded to 500 nodes, 1,000 edges,
and 1,048,576 bytes per source. Malformed, oversized, missing, or path-escaping
inputs yield a partial result with compact source errors rather than invented
links.

## Evidence and priority

Requirements are evidenced only when a mission completion receipt verifies
against its mission, validation manifest, and evidence hashes. A green build,
node label, filename, or graph position never creates coverage.

The recommendation is selected in this exact order:

1. `initialize_graph` — no readable local graph nodes.
2. `rerun_invalid_proof` — a content-addressed proof is stale.
3. `resolve_blocked_gate` — a declared proof plan contains `BLOCK`.
4. `run_required_validation` — a declared proof plan contains `RUN`.
5. `collect_completion_evidence` — a requirement lacks valid completion evidence.
6. `review_verified_graph` — all represented requirements have valid completion evidence.

Graph Ops does not execute validation, change a plan disposition, approve a
mission, publish, deploy, sign, send a message, access a credential, or grant a
connector. The authoritative Product Mission ledger, proof receipts, and trace
verifiers remain separate; Graph Ops only renders their current local facts.

## LangGraph optimization path

LangGraph remains the durable execution engine; Graph Ops is the independent
evidence and governance plane around it. A framework adapter should project
LangGraph checkpoint history into `factory.graph-lineage.v1` without copying
raw state values:

- map `thread_id`, `checkpoint_id`, `parent_config`, `metadata.step`, `next`,
  and task results into lineage identity, ordering, routing, and node facts;
- hash state values locally and retain only keyed digests and monotonic
  versions in the portable receipt;
- consume checkpoint and task stream modes for live progress while sealing a
  final lineage receipt for deterministic comparison;
- model subgraphs as nested lineage, respecting their own checkpointer boundary
  so a recovery preview never claims finer rewind granularity than LangGraph
  persisted; and
- translate a reviewed recovery into a LangGraph fork only after a separate
  named, expiring, signed approval. Replayed downstream nodes may repeat model
  calls, API requests, and interrupts, so side-effect idempotency remains a
  runtime gate.

This division avoids rebuilding persistence while giving LangGraph runs the
same contradiction, proof, anomaly, authority, and signed-review semantics as
native Code Factory missions.

When two verified lineage receipts exist for the same graph, Graph Ops adds a
semantic-forensics lane. It shows the first state divergence, deterministic
stale-read/parallel-write/duplicate-side-effect findings, and a read-only
counterfactual recovery preview. See [Graph Forensics](GRAPH_FORENSICS.md).

## Exact change impact

`factory graph impact --changed <path>` is the fast professional path after a
change. It follows only explicit `input_to` artifact edges from the supplied
workspace-relative paths to recorded proof receipts, then shows three distinct
sets: matched proofs, verified-current matches, and stale matched proofs that
belong in the rerun set. It also names declared gates already linked to those
proofs.

It does not use filename heuristics to declare a proof irrelevant, run a gate,
or silently skip validation. An unmatched path is reported as unmatched rather
than being claimed safe. This is an impact map, not a measured time or token
savings claim.

## Measurement boundary

Graph Ops does not claim time, token, cost, or productivity savings. Continue
to use paired savings receipts for those values; missing observations remain
unknown.
