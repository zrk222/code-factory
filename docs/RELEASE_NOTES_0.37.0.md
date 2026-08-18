# Code Factory 0.37.0

## Counterexamples, Guardrails, and Temporal Resilience

Code Factory 0.37.0 turns three common sources of AI-assisted delivery risk
into small, deterministic, reviewable evidence layers that appear together in
Unified Graph Ops.

- `factory counterexample plan|verify` compiles negative proof obligations from
  declared requirements. The verifier rejects tampered, stale, or hollow plans
  instead of treating a passing happy path as sufficient evidence.
- `factory guardrail evaluate|verify` reads only independently promoted,
  exact-scope, exact-purpose continuity metadata. It redacts remembered content
  and never creates, updates, migrates, or initializes the continuity store.
- `factory resilience plan|verify` derives bounded stale-read, parallel-write,
  duplicate-effect, retry-replay, and checkpoint-replay schedules from sealed
  Graph Ops lineage.
- Unified Graph Ops projects the evidence state and its next action in one
  local surface. Counterexample plans, guardrail evaluations, and resilience
  plans are all read-only: no source write, repair, execution, approval, merge,
  publication, deployment, credential, connector, or external-message
  authority is added.

## Install

```powershell
pip install factoryline-code-factory==0.37.0
factory graph ops --root . --json
```

See [Counterexamples, Guardrails, and Temporal Resilience](COUNTEREXAMPLE_GUARDRAIL_RESILIENCE.md)
for the complete contract and CLI examples.
