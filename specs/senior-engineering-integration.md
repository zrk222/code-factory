# Spec: senior-engineering-integration
Status: draft
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Add seven provider-neutral Code Factory capabilities to the 0.46.3 core: verify
independently collected execution attestations, evaluate a versioned real-defect
benchmark corpus, and produce a dependency-aware plan that routes safe
incremental work without weakening proof reuse; replay exact failures, compare
repairs with negative controls, explain evidence reuse across all relevant
fingerprints, and create actionable failure briefings. Developers get
trustworthy observations, measurable quality, faster feedback, and a usable
next action while human release authority remains unchanged.

### User roles
- Developer: supplies a candidate, signed plan, benchmark corpus, or proof manifest.
- Reviewer: verifies receipts, benchmark quality, and incremental/full equivalence.
- External runner: may collect observations but cannot alter the contract or release.

## Declared facts
- `attestation_binding_valid`: candidate, plan, runner, executable, nonce, and evidence digests match the signed contract.
- `attestation_fresh`: issuer is trusted, the attestation is unexpired, and the nonce has not been seen before.
- `attestation_observation_complete`: cleanup, resource, platform, and terminal observations are present.
- `benchmark_contract_valid`: every case has immutable source, expected outcome, and replay metadata.
- `benchmark_result_correct`: every buggy/fixed result matches its expected outcome.
- `dependency_closure_known`: every input and transitive dependency is declared and hash-bound.
- `reuse_receipt_exact`: proof key, inputs, outputs, toolchain, environment, and assurance level match a verified green receipt.
- `side_effects_possible`: the requested gate can mutate shared state or contact an uncontrolled external service.
- `shadow_equivalent`: incremental and full plans checked the same obligations and findings.
- `replay_contract_exact`: source, dependencies, policy, input files, argv, and sealed contract digest match the approved replay manifest.
- `repair_comparison_valid`: the original failure reproduces, the repair passes, and every negative control still fails under the same contract.
- `reuse_facts_exact`: policy, dependencies, toolchain, environment, receipt, and changed-input facts are known and equal.
- `failure_brief_actionable`: every finding points to evidence and includes affected scope, uncertainty, and a runnable reproducer when available.
- `replay_execution_requested`: the operator explicitly supplied `--execute`.
- `repair_original_failure_reproduced`: the buggy leg observed its non-zero expected exit.
- `repair_fixed_passed`: the repaired leg observed its zero expected exit.
- `repair_negative_controls_failed`: every negative control observed its non-zero expected exit.
- `repair_expectations_reviewed`: a changed expectation has an approving reviewer and non-empty reason.
- `reuse_side_effect_free`: the gate declares read-only and no side effects.
- `failure_brief_evidence_complete`: findings, evidence references, scope, next fix, and uncertainty are present.

### Declared bounds
- Replay source trees contain at most `1024` files and `33554432` bytes; each
  preview is at most `2048` bytes, argv contains at most `64` items, and the
  environment contains at most `32` entries.
- Replay and comparison identifiers are at most `128` characters; expected
  exits are in `-255..255`; replay timeout is `1..300` seconds.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- The system shall validate an independent execution attestation against an exact candidate, plan, runner identity, evidence digests, expiry, and nonce and emit `ATTESTATION_BINDING_RECEIPT`.
- If `ATTESTATION_INCOMPLETE_RECEIPT` is required when `attestation_observation_complete` is false, the system shall return `E_ATTESTATION_INCOMPLETE` and shall not mark the observation verified.
- When `BENCHMARK_CONTRACT_RECEIPT` is required while `benchmark_contract_valid` is false, the system shall return `E_BENCHMARK_CONTRACT` and shall not compute quality metrics.
- If a known-defect case passes or a clean control fails, the system shall return a closed failure with an exact case identifier and replay data and emit `DEFECT_CASE_RECEIPT`.
- When a proof manifest is planned, the system shall derive dependency-aware RUN, REUSE, SKIP, or BLOCK decisions from declared input closure and assurance level and emit `DAG_ROUTE_RECEIPT`.
- If dependency closure is unknown, stale, revoked, mutable, or side-effecting, the system shall route to RUN or BLOCK, shall not reuse the receipt, and shall emit `CLOSURE_BLOCK_RECEIPT`.
- The system shall emit bounded JSON receipts with canonical SHA-256 digests and no secrets, prompts, raw logs, or release authority and emit `BOUNDED_RECEIPT`.
- The system shall emit `VERSIONED_COMMAND_RECEIPT` for each capability through Python interfaces and `factory senior` CLI commands.
- The system shall emit a replay receipt only after an explicit execution request runs the declared argv in a fresh temporary workspace and child interpreter invocation with `shell=False`, bounded timeout/output limits, and a secret-free environment; the receipt shall state that this is not a kernel/container sandbox and emit `REPLAY_BOUND_RECEIPT`.
- When a `REPAIR_COMPARISON_RECEIPT` is executed, the system shall emit `PASS` only when the original failure reproduces, the repaired leg passes, and every negative control fails; changed expectations shall block without an approving reviewer and non-empty reason.
- When a `REUSE_EXPLANATION_RECEIPT` is requested, the system shall emit per-gate `REUSE`, `RUN`, or `BLOCK` after comparing policy, dependency, toolchain, environment, receipt, and changed-input fingerprints; any unknown or missing input shall emit `RUN`, and any side-effecting gate shall emit `BLOCK`.
- The system shall emit a failure briefing containing what broke, affected scope, a reproducer when available, next fix, uncertainty, and receipt references without inferring ownership or impact and emit `FAILURE_BRIEF_RECEIPT`.
- The system shall emit `PLATFORM_RESULT_RECEIPT` for Windows, Linux, and macOS and shall label an unavailable independent backend `UNAVAILABLE`.
- The system shall emit memory peak as integer bytes with 0 minimum, cleanup as boolean, and latency as integer milliseconds with 0 minimum; absent values shall be null and emit `RESOURCE_OBSERVATION_RECEIPT`.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: forged attestation is rejected
  Given an attestation whose evidence digest or runner identity differs from the signed plan
  When the attestation is verified
  Then verification fails closed with a stable error code

Scenario: valid independent observation is accepted for review only
  Given an exact candidate, unexpired plan, distinct runner, executable digest, cleanup evidence, and matching artifact digests
  When the attestation is verified
  Then the receipt is marked observed and release authority remains false

Scenario: benchmark catches a real defect and passes its fix
  Given a buggy/fixed pair with a human-owned expected finding
  When both cases are evaluated
  Then the buggy case fails for the expected code and the fixed case passes

Scenario: unsafe reuse is blocked
  Given a proof whose dependency closure is incomplete or whose assurance level changed
  When an incremental plan is created
  Then the disposition is RUN or BLOCK, never REUSE

Scenario: equivalent incremental plan is measured
  Given a fixed change corpus and a full-plan baseline
  When shadow comparison runs
  Then every required finding and obligation agrees before an incremental skip is reviewed

Scenario: replay cannot inherit signing material
  Given a replay manifest with an exact source, dependency, policy, input, and contract digest
  When the operator explicitly executes the replay command
  Then the candidate runs only in a fresh temporary process workspace with a bounded secret-free environment
  And the receipt states that no kernel or container sandbox is claimed

Scenario: a repair cannot weaken a negative control
  Given an original failing replay, a proposed fixed replay, and one negative control bound to the same contract
  When the repair comparison executes
  Then the original failure reproduces, the repair passes, and the negative control fails
  And any changed expectation without review blocks the comparison

Scenario: unknown evidence must run again
  Given a read-only green proof receipt without a policy or dependency fingerprint
  When evidence reuse is explained
  Then the disposition is `RUN` and the receipt lists the missing policy and dependency facts

Scenario: a reviewer gets a useful failure handoff
  Given a failed replay receipt with a runnable argv
  When a failure briefing is built
  Then what broke, affected scope, reproduction, next fix, uncertainty, and receipt evidence are present

Scenario: every senior requirement has a traceable validator anchor
  Given a declared senior-engineering request
  When the bounded validator runs
  Then the system emits `ATTESTATION_BINDING_RECEIPT`
  And the system emits `ATTESTATION_INCOMPLETE_RECEIPT`
  And the system emits `BENCHMARK_CONTRACT_RECEIPT`
  And the system emits `DEFECT_CASE_RECEIPT`
  And the system emits `DAG_ROUTE_RECEIPT`
  And the system emits `CLOSURE_BLOCK_RECEIPT`
  And the system emits `BOUNDED_RECEIPT`
  And the system emits `VERSIONED_COMMAND_RECEIPT`
  And the system emits `REPLAY_BOUND_RECEIPT`
  And the system emits `REPAIR_COMPARISON_RECEIPT`
  And the system emits `REUSE_EXPLANATION_RECEIPT`
  And the system emits `FAILURE_BRIEF_RECEIPT`
  And the system emits `PLATFORM_RESULT_RECEIPT`
  And the system emits `RESOURCE_OBSERVATION_RECEIPT`
```

## SHOULD — Technical/structural
- ADR references: existing runtime-audit, proof-reuse, Graph Ops, and enterprise receipt boundaries.
- Data model: `factory.execution-attestation.v1`, `factory.defect-benchmark.v1`, `factory.incremental-plan.v1`, `factory.replay-receipt.v1`, `factory.repair-comparison.v1`, `factory.evidence-reuse.v1`, and `factory.failure-brief.v1` receipts under `.factory/`.
- API contract: `factoryline.independent_execution`, `factoryline.benchmark_lab`, `factoryline.incremental_scheduler`, and `factoryline.senior_assurance`; CLI `factory senior attest|benchmark|schedule|shadow|replay|repair|reuse|brief`.

## SHOULD NOT — Implementation details
<!-- Leave the "how" to the plan/tasks unless it is a systemic invariant -->

## Decision logic (factory candidates)
<!-- Ordered business rules over extracted facts. specline handoff compiles
     these via HSF instead of letting agents improvise them. -->
| # | if | then |
|---|----|------|
| 1 | `attestation_binding_valid` is false | return `BLOCK` with `E_ATTESTATION_BINDING` |
| 2 | `attestation_fresh` is false | return `BLOCK` with `E_ATTESTATION_FRESHNESS` |
| 3 | `attestation_observation_complete` is false | return `INCOMPLETE` with `E_ATTESTATION_INCOMPLETE` |
| 4 | `benchmark_contract_valid` is false | return `INCOMPLETE` with `E_BENCHMARK_CONTRACT` |
| 5 | `benchmark_result_correct` is false | return `FAIL` with a case-level finding and replay |
| 6 | `dependency_closure_known` is false | return `RUN` with `PROOF_RELEVANCE_FAIL_CLOSED` |
| 7 | `side_effects_possible` is true | return `BLOCK` with `PROOF_SIDE_EFFECT_REUSE_REFUSED` |
| 8 | `reuse_receipt_exact` is true | return `REUSE` with `PROOF_RECEIPT_REUSED` |
| 9 | `reuse_receipt_exact` is false | return `RUN` with `PROOF_EXECUTION_REQUIRED` |
| 10 | `shadow_equivalent` is true | expose the incremental candidate for human review with authority false |
| 11 | `replay_contract_exact` is false | return `BLOCK` with `E_REPLAY_CONTRACT_INCOMPLETE` |
| 12 | `replay_execution_requested` is false | return `PLAN_ONLY` and run no candidate |
| 13 | `repair_original_failure_reproduced` is false, `repair_fixed_passed` is false, or `repair_negative_controls_failed` is false | return `FAIL` with a finding linked to the leg receipt |
| 14 | `repair_expectations_reviewed` is false | return `BLOCK` with `E_EXPECTATION_REVIEW_REQUIRED` |
| 15 | `reuse_facts_exact` is false | return `RUN` with `UNKNOWN_INPUT_REQUIRES_EXECUTION` |
| 16 | `reuse_side_effect_free` is false | return `BLOCK` with `SIDE_EFFECT_REUSE_REFUSED` |
| 17 | `failure_brief_evidence_complete` is false | emit an uncertainty marker; never claim a complete briefing |
