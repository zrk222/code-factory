# Spec: p1-resumable-factory-mission
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Run and resume one SpecLine, ForgeLine and FactoryLine delivery mission through the existing mission graph and durable incident driver.

### User roles
- The mission owner authorizes work and can pause or redirect it.
- A registered host executes declared stages; an independent validator verifies results.

### Requirements (EARS)
- The system shall store one job binding to the verified mission SHA-256, SpecLine intent envelope SHA-256, source revision and authorized phase plan, verified by `job_intent_binding`.
- The system shall return the recorded action status from the registered host before launching and reject an unknown outcome when an approved job is resumed, verified by `effect_reconciliation`.
- The system shall emit completion only after the current native intent trace and candidate-bound FactoryLine proof both verify when ForgeLine reports completion, verified by `proof_bound_completion`.
- The system shall return a REUSE disposition only after its existing verifier passes when an exact current proof is reusable, verified by `verified_proof_reuse`.
- The system shall return execution evidence for admitted waves with at most eight CPU slots and explicitly reserved memory when two or more independent nonmutating proof checks are eligible, verified by `resource_bounded_checks`.
- The system shall return one ordered operator timeline with verified checkpoints, unfinished work, intervention count and one next action, verified by `operator_timeline`.
- The system shall reject a dispatch and record an evidence gap if the mission, intent, candidate, permission or proof changes or becomes unverifiable, verified by `stale_job_fails_closed`.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: resume an approved delivery after an interrupted stage
  Given one approved mission with a verified SpecLine intent and one registered native host
  When a ForgeLine effect completes before its local checkpoint is written
  Then `effect_reconciliation` observes the same action without launching it twice
  Then `job_intent_binding` joins both stores to the exact mission and intent
  Then `proof_bound_completion` verifies ForgeLine and FactoryLine evidence against one candidate
  Then `verified_proof_reuse` reuses current evidence and rejects changed inputs
  Then `operator_timeline` shows recovery, verification, interventions and the next action

Scenario: admit independent proof work by resource reservation
  Given at most eight registered slots and explicit CPU and memory reservations
  When two independent nonmutating checks are eligible and a third has a dependency
  Then `resource_bounded_checks` admits only checks that fit and delays dependent checks
  Then `stale_job_fails_closed` preserves the last verified checkpoint if inputs or authority change
```

## SHOULD — Technical/structural
- Reuse the mission ledger, WorkflowEventStore, DurableIncidentDriver, native handoff verification, proof evaluator and incremental scheduler.
- Compare the same candidate in serial and parallel: actual wall time, completed checks, verified reuse, peak admitted resources, recovery attempts and logged interventions. Distinguish observed process resources from admission reservations.
- Compare existing callers before removing duplicate behavior.

## SHOULD NOT — Implementation details
- Do not add a daemon, separate job ledger, untrusted callback import or automatic approval.
- Do not claim fresh scanner precision, release approval or OS isolation from a local mission receipt.

## Decision logic (factory candidates)
Decision facts: `binding_current: boolean`, `outcome_known: boolean`,
`proof_reusable: boolean`, `wave_fits: boolean`, `completion_verified: boolean`.

| # | if | then |
|---|----|------|
| 1 | `binding_current` == false | BLOCK_BEFORE_DISPATCH |
| 2 | `outcome_known` == false | REQUIRE_RECONCILIATION |
| 3 | `proof_reusable` == true | REUSE_CURRENT_PROOF |
| 4 | `wave_fits` == true | ADMIT_READ_ONLY_WAVE |
| 5 | `completion_verified` == true | RECORD_VERIFIED_COMPLETION |
