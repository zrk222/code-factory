# Research integration: detection, repair and durable operation

This design adapts the supplied activation-intervention and persistent-agent
research to Code Factory. It distinguishes executable evidence from model
assessments and planned capabilities. It is not a safety certification or an
adopted external standard. The supplied SAAC-101 title has no supplied
standards-body provenance.

## Implementation order and acceptance

| Priority | Integration | Existing foundation | Required acceptance |
| --- | --- | --- | --- |
| 1 | Behavioral intervention report | `fix_workflow`, `senior_assurance` | Reproduce the defect, test the repair, preserve negative controls, bind every observation to its receipt. Plan-only execution reports no observed successes. |
| 2 | Evidence-led Jev triage | `jev_classifier`, `analysis_evidence` | Use exact source, tool, trace and contract hashes; retain unresolved claims and contradictions. Model opinions cannot clear deterministic findings. |
| 3 | Selective reruns and context reuse | `context_efficiency`, evidence reuse | Reuse only hash-current inputs, environment and evaluator identities. Report actual rerun counts and measured latency, separately from token estimates. |
| 4 | Durable incident executor | SQLite workflow event store with ownership epochs and reconciliation, loop budget ledger, repair sandbox | Connect durable claims to an idempotently discoverable driver and retained result. Prove crash recovery, expired leases, concurrent workers, duplicate events and ambiguous external outcomes. |
| 5 | Dynamic execution containment | Capability contracts, approved sandbox repair | Check current permissions at dispatch; reject revoked or stale grants. A prompt or model classification alone is insufficient enforcement. |
| 6 | Operator presentation | Existing trace and repair receipts | Show the reproduced failure, repair outcome, controls, missing evidence, cost and next action. Preserve unknown values and explicit consent for external effects. |

The existing fix workflow runs bounded original, repaired and negative-control
replays. Its behavioral-intervention report describes those observations; it
does not establish scanner precision, recall or neural causality. Repeated
reliability and independently labelled corpus measurements remain separate
experiments with disclosed sample counts and exclusions.

## Detection and repair experiments

For each applicable audit lane, retain a clean example, one controlled defect,
the repaired candidate and unrelated negative controls. Keep requirements and
the evaluator fixed while changing the candidate. Record source and dependency
hashes, execution environment, timeout, exit status, output completeness and
receipt identity. A timeout or unavailable tool is incomplete evidence.

Include benign lookalikes and withheld repositories to measure false positives.
Separate static findings from executed evidence, and report precision, recall,
abstentions and sample sizes by failure category. An AI-generated label is not
independent human ground truth. Do not select an aggregate accuracy target by
discarding unresolved cases.

For repairs, reproduce the original failure before crediting a correction.
Reject repairs that weaken the test, remove the requirement, suppress diagnostics
or change expected outcomes without the existing reviewed expectation-change
path. Additional repeated trials must record each result rather than promote one
successful attempt to reliable recovery.

## Durable execution and efficient recovery

Bind an incident to its source revision, policy version, evidence and budget.
Use transactional checkpoints, leases with fencing tokens, and unique operation
identities. Completed work is reusable only while its bound inputs remain valid.
Store large logs outside the task's compact state and retain their hashes.

Before resuming an external mutation, reconcile its provider-side status. A local
lock cannot guarantee exactly-once remote execution: a crash can occur after the
effect and before recording success. Unknown outcomes require reconciliation;
they must not trigger blind replay. Test that crash window explicitly.

Context compaction must use a versioned snapshot plus subsequent event replay so
concurrent changes are not lost. A shared JSON file alone is not a concurrency
protocol. No detached production monitor or scheduled repair is enabled by this
design; those require explicit configuration and authorization.

Host-approved repair dispatch carries a live identity/approval verifier into
effect boundaries and cooperative execution polling. Loss of that authority
stops further work while preserving required cleanup. Polling is not immediate
revocation and cannot undo effects already performed. Local owner-approved CLI
execution retains its separate, explicitly unauthenticated identity boundary.

## Jev and model-internal research

Jev can prioritize uncertain evidence, explain contradictions and suggest a
bounded experiment. Deterministic validation and execution-time permissions
remain authoritative. Track model and prompt versions, raw structured output,
input evidence hashes, disagreements, abstentions, latency and reported cost.
Evaluate benign commands and adversarial inputs before granting operational use.
The supplied low-cost figures are examples, not measured CF costs.

Activation patching and feature steering need a self-hosted model with suitable
internal hooks. Gateway text-generation access does not itself establish those
capabilities. Keep this research separate from native code audits. Compare
unmodified, prompt-only and steered models on held-out coding tasks; measure
false clears, regressions, latency and memory. Reset generation state and KV
cache between experimental conditions. Detaching a steering vector does not
undo tokens or cache entries already produced.

Patching conclusions depend on corruption methods and metrics; a restored
prediction is evidence for a particular intervention, not a general safety
guarantee. Steering can cause off-target effects and capability degradation.

Primary research:

- [Activation-patching metrics and methods](https://arxiv.org/abs/2309.16042)
- [Feature-steering evaluation and limitations](https://www.anthropic.com/research/evaluating-feature-steering)
- [Persona-vector research](https://www.anthropic.com/research/persona-vectors)
- [Vercel AI Gateway interface and observability](https://vercel.com/docs/ai-gateway)

No speedup, accuracy improvement, sandbox guarantee or release readiness follows
from adopting this design. Each requires the corresponding measured acceptance
evidence above.
