# Spec: instruction-learning-loop
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Code Factory shall refine task-specific worker instructions from outcome
evidence without transferring hidden reasoning or granting agents authority to
validate or promote their own instructions. Ordered milestones shall make the
earliest incomplete unit observable and block later work.

### Requirements (EARS)

- The system shall return `LEARNING_TASK_BOUND` and `MILESTONE_GATES_BOUND` after binding an owner, objective, ordered milestones, and exact criteria.
- The system shall return `FRESH_WORKER_CONTEXT` with empty prior reasoning and prior worker output fields.
- The system shall return `PROMOTED_INSTRUCTIONS_ONLY`; unvalidated candidates shall never enter a worker packet.
- When a worker proposes instructions, the system shall return `CANDIDATE_UNTRUSTED` and deny activation, promotion, and Opinion Dock edits.
- If the candidate worker and validator identities match, validation shall fail with `VALIDATOR_IDENTITY_DISTINCT`.
- If any criterion is absent, duplicated, failed, or lacks local hash-bound evidence, validation shall fail with `MILESTONE_VALIDATION_INCOMPLETE`.
- If worker, validator, and owner are not three distinct identities, promotion shall fail with `PROMOTER_IDENTITY_DISTINCT`.
- When all criteria pass and the recorded owner promotes, the system shall return `AKU_ACTIVATED`, `HUMAN_PROMOTION_BOUND`, and `MILESTONE_GATE_PASSED`.
- The system shall return `MILESTONE_ORDER_BLOCKED` for every worker-packet or candidate request whose ordered milestone predecessors do not each have a valid promotion receipt.
- When outcome or validation evidence changes after binding, promotion shall fail with `HASH_INVALID`.
- When an instruction candidate is stored, the system shall reject with `INSTRUCTION_CANDIDATE_INVALID` every edit whose dimension is not exactly one of `d1_context_assembly`, `d2_tool_interaction`, `d3_generation_control`, `d4_orchestration`, `d5_memory_management`, or `d6_output_processing`.
- When an ASHA, Hyperband, or BOHB experiment is planned, the system shall return `CORRECTNESS_FIRST_OBJECTIVE` with correctness on the inclusive `0.0`-to-`1.0` scale maximized before the nonnegative tie-breakers cost (`>= 0.0` USD), tokens (`>= 0` tokens), and latency (`>= 0.0` seconds) are minimized.
- The system shall return `EXTERNAL_RUNNER_NO_AUTHORITY` for every experiment plan and set execution, credential access, training, and instruction promotion authority to false.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Improve instructions without inheriting reasoning noise
  Given a task with one promoted instruction set
  When a new isolated worker packet is created
  Then it contains the task facts and promoted instructions
  And it contains no prior reasoning or worker outputs

Scenario: Reject self-certified learning
  Given a worker-authored instruction candidate
  When the same identity attempts validation
  Then validation fails and no active AKU is written

Scenario: Advance only through proven milestones
  Given the milestone at position 1 lacks a promotion and another milestone is at position 2
  When a worker packet for the milestone at position 2 is requested
  Then the request fails with `MILESTONE_ORDER_BLOCKED` naming the milestone at position 1

Scenario: Use Harbor results as evidence without outsourcing authority
  Given a Harbor or Terminal-Bench result file beneath the workspace
  When a distinct validator binds it to a milestone criterion
  Then Code Factory hashes the result as evidence
  And Harbor does not gain instruction-promotion authority

Scenario: Every requirement has an observable validator marker
  Given the governed instruction-learning contract
  When strict validator mutation runs
  Then contract markers include `LEARNING_TASK_BOUND`, `MILESTONE_GATES_BOUND`, `FRESH_WORKER_CONTEXT`, `PROMOTED_INSTRUCTIONS_ONLY`, `CANDIDATE_UNTRUSTED`, `INSTRUCTION_CANDIDATE_INVALID`, `VALIDATOR_IDENTITY_DISTINCT`, `MILESTONE_VALIDATION_INCOMPLETE`, `PROMOTER_IDENTITY_DISTINCT`, `AKU_ACTIVATED`, `HUMAN_PROMOTION_BOUND`, `MILESTONE_GATE_PASSED`, `MILESTONE_ORDER_BLOCKED`, `HASH_INVALID`, `CORRECTNESS_FIRST_OBJECTIVE`, and `EXTERNAL_RUNNER_NO_AUTHORITY`
```

## SHOULD - Technical and structural

- CLI contract: `factory learning init|packet|propose|validate|promote`.
- Active instructions use the AKU fields intent, procedure, tools, metadata,
  governance, continuations, and validators.
- The initial governance classification is `human_controlled`; a promoted AKU
  is `supervised`. Autonomous classification requires separately shipped
  invariant-validator history and is outside this lane.
- Harbor is an optional evidence producer. The official Terminal-Bench command
  can run independently, and its exported result is copied beneath the task
  workspace before validation. Code Factory does not read API keys, launch
  sandboxes, submit leaderboards, train models, or accept a score as promotion.
- `factory learning experiment` writes a scheduler-neutral contract. `asha` is
  the default for asynchronous parallel evaluation; `hyperband` selects the
  synchronous bracket policy; `bohb` requests a guided sampler plus Hyperband.
  Ray Tune or another adapter performs execution separately.

## SHOULD NOT - Implementation details

- Do not ingest worker scratchpads, chain-of-thought, or hidden reasoning.
- Do not auto-run Harbor, Docker, cloud sandboxes, RL, SFT, or model providers.
- Do not let benchmark score replace milestone-specific acceptance criteria.
- Do not let instruction promotion edit the owner-controlled Opinion Dock.

### Authorized bounded constants

- Structured text inputs use UTF-8; task ids normalize to ASCII `a-z`, `0-9`, and hyphens and are at most 64 characters.
- A task contains 1-50 milestones; each milestone contains 1-100 criteria; each candidate contains 1-100 instruction edits.
- Candidate, validation, and experiment filenames use the first 12 SHA-256 hexadecimal characters; worker-packet filenames use the first 10.
- Experiment defaults are max resource 50 evaluation iterations, grace period 5 iterations, reduction factor 3, maximum concurrency 4 trials, and 20 samples.
- Experiment bounds are max resource 1-10,000 iterations, grace period 1 through max resource, reduction factor 2-10, maximum concurrency 1-1,000 trials, and samples 1-100,000.
- A maximum concurrency of `1001` trials is an explicit invalid-bound test mutation.
- SSAT symbol-scope limits are 45 lines for packet creation, 55 lines for candidate creation, and 60 lines for validation.
