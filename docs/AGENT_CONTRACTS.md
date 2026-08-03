# Agent contracts and evidence rails

Code Factory keeps agent customization reviewable at the Core 5 seam: model,
prompt, tools, harness, and handoff. A contract is a small JSON manifest,
validated by `factory agent contract`, canonicalized, and bound to a SHA-256
digest. It describes what an agent may use; it does not contain credentials
and it does not grant deployment or provider-spend authority.

```bash
factory agent contract .factory/agent-contract.json --json
```

The contract enforces a 12,000-token context ceiling, a 5,000 ms model-latency
ceiling, and a $0.50 per-run ceiling. Tool allow/deny sets must be disjoint;
isolated context walls cannot include creator scratchpads or hidden reasoning.
When `.factory/agent-contract.json` exists, `factory assemble` validates it
before any module is run and fails closed on drift or an invalid rail.

Creator/verifier missions additionally carry an adapter attestation. The
attestation binds the mission digest, distinct creator/verifier identities,
fresh-session state, an isolated context wall, and an evidence digest:

```bash
factory agent attestation .factory/missions/<id>/adapter-attestation.json --json
```

Mission completion refuses to close without this receipt. The receipt proves
that the adapter supplied the declared wall; it does not claim that the
external model or provider was called.

## Telemetry reconciliation

FactoryLine reconciles `receipts/`, `.factory/runs/`, `.factory/traces/`, and
`.factory/meter.jsonl` without publishing feature names, prompts, paths, or
raw logs:

```bash
factory telemetry inventory --root . --json
factory metrics --root . --json
```

Conflicting run identities are surfaced as conflicts. Missing cost, token, or
queue telemetry remains unknown; it is never turned into zero or a savings
claim.
