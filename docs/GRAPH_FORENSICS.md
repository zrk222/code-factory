# Graph Forensics

Graph Forensics is Code Factory's read-only semantic debugger for graph runs.
It verifies two supplied `factory.graph-lineage.v1` receipts, finds their first
meaningful divergence, detects state/concurrency anomalies, follows the affected
state keys through the downstream causal cone, and prepares a human-reviewed
recovery fork.

The repository includes deterministic sample inputs under
`examples/graph-forensics/`. Seal them into a workspace and open Graph Ops to
exercise the real forensic cockpit:

```powershell
factory graph lineage-seal --run-id baseline --graph-id checkout `
  --steps examples/graph-forensics/baseline-steps.json `
  --out .factory/graph-runs/01-baseline.lineage.json
factory graph lineage-seal --run-id candidate --graph-id checkout `
  --steps examples/graph-forensics/candidate-steps.json `
  --out .factory/graph-runs/02-candidate.lineage.json
factory studio --root .
```

```powershell
factory graph lineage-seal --run-id good-001 --graph-id checkout `
  --steps steps.json --out .factory/graph-runs/good.lineage.json --json
factory graph lineage-mission .factory/missions/M-001/mission.json --root . `
  --run-id mission-001 --out .factory/graph-runs/mission-001.lineage.json --json
factory graph lineage-verify .factory/graph-runs/good.lineage.json --json
factory graph forensics --baseline .factory/graph-runs/good.lineage.json `
  --candidate .factory/graph-runs/bad.lineage.json --json
factory graph forensics --baseline good.json --candidate bad.json --mermaid
```

Each step declares its sequence, superstep, node, checkpoint, state reads and
writes, evidence, side effects, and routing decision. State values are never
required; receipts bind their SHA-256 digests and versions instead.

`steps.json` is either a JSON list or an object with a `steps` list. Sealing is
an explicit local write to the requested output; verification, comparison,
Graph Ops, Mermaid rendering, and recovery planning remain read-only.

`lineage-mission` requires the native mission ledger to pass its existing event
hash-chain and bound-receipt checks, then translates its guarded control-state
transitions automatically. It does not claim visibility into undeclared model
state or tool internals; non-Code-Factory runtimes use `lineage-seal` or a
framework adapter that supplies the same contract.

The deterministic anomaly pass reports:

- `STALE_READ` and `STALE_WRITE` when a node used an older recorded version;
- `PARALLEL_WRITE_CONFLICT` when parallel writers lack one common declared
  reducer; and
- `DUPLICATE_SIDE_EFFECT` when a completed effect appears more than once.

The recovery plan never changes a checkpoint or invokes a graph. It names the
checkpoint before the first divergence, the causal nodes that would need to run
again, and the evidence those nodes invalidate. A human must approve any actual
fork, and the runtime must independently enforce side-effect idempotency.

This is semantic time travel, not ordinary telemetry: it explains which state
changed, which node changed it, what evidence it consumed, how the change
propagated, and the bounded recovery branch. It does not infer correctness from
graph position or claim time, token, cost, or productivity savings.
