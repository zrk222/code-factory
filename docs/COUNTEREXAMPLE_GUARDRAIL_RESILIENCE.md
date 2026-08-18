# Counterexamples, memory guardrails, and temporal resilience

These three surfaces extend Code Factory's evidence model without granting an
agent more authority. They are local JSON planners and verifiers: they do not
call a model, run a generated command, edit source, retrieve memory content,
promote a record, approve a repair, or contact an external service.

## 1. Compile the cases a test must reject

Create a small source file containing only reviewed requirement identifiers,
statements, and risk tags. The compiler emits one negative-proof obligation for
each declared requirement/tag pair. It never invents a test command.

```json
{
  "schema": "factory.counterexample-source.v1",
  "id": "checkout-approval",
  "requirements": [
    {
      "id": "REQ-001",
      "statement": "Only an approver can release a change.",
      "risk_tags": ["authorization", "validation"]
    }
  ]
}
```

```powershell
factory counterexample plan specs/checkout.counterexamples.json `
  --root . --out .factory/counterexamples/checkout.json --json
factory counterexample verify .factory/counterexamples/checkout.json `
  --root . --json
```

`COUNTEREXAMPLE_PLAN_VERIFIED` means the exact declared pair set is present.
`HOLLOW_COUNTEREXAMPLE` means a sealed plan was syntactically intact but one or
more derived obligations no longer match the source. It is not a claim that any
test was executed or that the product is ready.

Supported tags are `boundary`, `authorization`, `idempotency`, `temporal`,
`state`, and `validation`.

## 2. Turn a promoted lesson into a scoped guardrail

Factory Continuity remains a metadata ledger, not a content store. An
independent reviewer promotes an evidence-bound record; a separate manifest
then maps that record to exact repository scope, purpose, and path prefixes.
Evaluation returns only redacted provenance facts.

```powershell
factory guardrail evaluate .factory/guardrails/checkout.manifest.json `
  --db .factory/continuity.sqlite3 `
  --tenant team-a --subject reviewer --purposes delivery-review@1 `
  --changed src/checkout/approve.py --json
```

An eligible record produces `active` only when its exact tenant, purpose,
scope, and path mapping match. A draft, expired, missing, or mismatched record
produces `GUARDRAIL_WITHHELD`. The output intentionally omits `memory_ref` and
`summary`; it cannot act as a back door to persistent agent context.

Use `factory guardrail verify evaluation.json --json` to verify the evaluation
hash and prove that its serialized rows do not expose those fields.

## 3. Plan stateful failure checks from graph lineage

Graph lineage already records declared reads, writes, checkpoints, and side
effects. The resilience planner derives bounded schedules for stale reads,
parallel writes, duplicate effects, retry replay, and checkpoint replay. The
schedules stay execution-locked.

```powershell
factory resilience plan .factory/graph-runs/checkout.lineage.json `
  --root . --out .factory/resilience/checkout.json --json
factory resilience verify .factory/resilience/checkout.json --root . --json
```

`TEMPORAL_RESILIENCE_PLAN_VERIFIED` says the schedule exactly reflects the
sealed lineage used to make it. It does not say a replay was performed or that
the graph is production-resilient. Stale, changed, or incomplete plans fail
closed.

## Graph Ops

Place generated plans and evaluations under the documented `.factory` paths
above. `factory graph ops --root . --json` projects them as typed, read-only
nodes and includes their verification counts in the graph facts. It does not
evaluate a continuity database, execute a counterexample, run a schedule, or
consume an authorization.
