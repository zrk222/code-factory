# Spec: ops-evidence-integration
Status: approved
SpecFactor-target: 0.75-2.5

## MUST — Functional core
### Description
Compose existing CF tools into source-bound pre-PR verification, repair history, and incident regression intake.

### User roles
- Repository maintainer requesting local verification.
- Coding agent consuming repair evidence.

### Requirements (EARS)
- When pre-PR verification is requested, the system shall return PASS only after reconciling every declared dependency gate with current execution or verified reuse, oracle evidence, and feature verification under the `pre_pr_evidence` acceptance contract.
- If a required gate is missing, failed, stale, or blocked, the system shall return a non-passing result with 0 merge or release authorizations under the `pre_pr_rejection` acceptance contract.
- When repair history is supplied, the system shall verify ordered receipt hashes and original-failure, control, contract, and candidate bindings before execution under the `repair_history` acceptance contract.
- When 3 executed repair attempts have failed under the default round budget, the system shall return STEP_BACK before executing attempt 4; planned attempts shall consume 0 executed rounds under the `repair_round_budget` acceptance contract.
- If a candidate repeats an executed failed candidate, the system shall return NO_PROGRESS without repeating execution under the `repair_no_progress` acceptance contract.
- When a reviewed incident supplies current replay and control evidence, the system shall emit an exposed-regression packet with source hashes and 0 execution authorizations under the `incident_packet` acceptance contract.
- If incident evidence is missing, changed, duplicated with conflicting content, or outside the workspace, the system shall reject intake under the `incident_rejection` acceptance contract.
- The system shall emit unchanged raw diagnostics and retain existing verification and human approval decisions across all 3 integrations under the `authority_preservation` acceptance contract.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Current pre-PR evidence
  Given every declared dependency gate has current evidence
  When pre-PR verification runs with valid oracle and feature receipts
  Then the result is PASS with 0 merge authorizations
Scenario: Incomplete pre-PR evidence
  Given 1 required dependency gate has stale evidence
  When pre-PR verification runs
  Then the result is non-passing
Scenario: Repair round budget
  Given 3 executed failed attempts and a round budget of 3
  When attempt 4 is requested
  Then the result is STEP_BACK with 0 commands executed
Scenario: Duplicate repair candidate
  Given a candidate repeats 1 executed failed candidate
  When repair verification is requested
  Then the result is NO_PROGRESS with 0 commands executed
Scenario: Incident regression intake
  Given current source-bound replay and control evidence
  When a reviewed incident is ingested
  Then 1 exposed-regression packet is produced with 0 execution authorizations
Scenario: Stale incident source
  Given 1 captured source hash has changed
  When incident intake is requested
  Then intake is rejected
```

```gherkin
Scenario: pre_pr_evidence
  Given the `pre_pr_evidence` acceptance contract
  When the declared behavior is checked
  Then the `pre_pr_evidence` requirements hold
Scenario: pre_pr_rejection
  Given the `pre_pr_rejection` acceptance contract
  When the declared behavior is checked
  Then the `pre_pr_rejection` requirements hold
Scenario: repair_history
  Given the `repair_history` acceptance contract
  When the declared behavior is checked
  Then the `repair_history` requirements hold
Scenario: repair_round_budget
  Given the `repair_round_budget` acceptance contract
  When the declared behavior is checked
  Then the `repair_round_budget` requirements hold
Scenario: repair_no_progress
  Given the `repair_no_progress` acceptance contract
  When the declared behavior is checked
  Then the `repair_no_progress` requirements hold
Scenario: incident_packet
  Given the `incident_packet` acceptance contract
  When the declared behavior is checked
  Then the `incident_packet` requirements hold
Scenario: incident_rejection
  Given the `incident_rejection` acceptance contract
  When the declared behavior is checked
  Then the `incident_rejection` requirements hold
Scenario: authority_preservation
  Given the `authority_preservation` acceptance contract
  When the declared behavior is checked
  Then the `authority_preservation` requirements hold
```

## SHOULD — Technical/structural
- Reuse existing scheduling, replay, oracle, repair, and incident modules.
- Preserve Python 3.10 compatibility, complexity at most 10, and module length at most 6000 lines.
- Expose integrations through existing CLI groups and JSON evidence boundaries.

## SHOULD NOT — Implementation details
- No scanner recognizers, label changes, automatic merge, deployment, network collection, or new core modules.
- Regression examples shall not be described as untouched held-out data.
