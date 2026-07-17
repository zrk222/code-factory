# Spec: signal-loop
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Code Factory shall add a local, deterministic signal-to-mission control layer.
It shall normalize owner-supplied signals, bind triage to a compact Architecture
Opinion Dock, require a Product Owner decision before promotion, and enforce an
independent creator-verifier completion contract. External connectors are data
adapters only and remain disabled until separately authorized and implemented.

### User roles

- Product Owner: owns the Opinion Dock and approves, rejects, or defers triage.
- Creator: works from the approved mission context and produces candidate code.
- Independent verifier: receives only the mission, diff, and declared evidence.
- Factory steward: maintains validators, budgets, architecture rules, and receipts.

### Requirements (EARS)

- The system shall return marker `SIGNAL_NORMALIZED_LOCAL_ONLY` after writing schema `factory.signal.v1` beneath `.factory/signals` without calling an external service.
- The system shall return marker `SIGNAL_PROVENANCE_BOUND` after recording source, capture authorization, observed time, content hash, and an untrusted-data classification.
- When identical source content is captured twice, the system shall return marker `SIGNAL_DEDUP_HASHED` and reuse the existing signal without appending a duplicate queue item.
- The system shall return marker `OPINION_DOCK_BOUND` after writing schema `factory.opinion_dock.v1` with owner, version, rules, routing profiles, and a content hash.
- If an Opinion Dock exceeds 2000 lines, the system shall return marker `OPINION_DOCK_LINE_BUDGET` with validity `false` and shall not triage a signal.
- When an owner changes a rule, the system shall return marker `OPINION_CORRECTION_APPEND_ONLY` after preserving the previous rule hash and correction rationale.
- When triage runs, the system shall return marker `TRIAGE_EXPLAINABLE` with every matched rule, score contribution, routing profile, and recommended decision.
- If a signal matches a hands-off rule, the system shall return marker `HANDS_OFF_RULE_ENFORCED` and recommended decision `blocked`.
- The system shall return marker `OWNER_DECISION_REQUIRED` for every machine-generated triage result and shall not promote an undecided signal.
- When a Product Owner records a decision, the system shall return marker `OWNER_DECISION_BOUND` after binding decision, rationale, owner, signal hash, triage hash, and Opinion Dock hash.
- When a mission owner approves, defers, or rejects bounded execution, the system shall return marker `MISSION_EXECUTION_APPROVAL_BOUND` after binding the mission file hash, mission content hash, owner, decision, rationale, and unchanged external-effect denials.
- When an approved signal has supplied requirements and Gherkin acceptance, the system shall return marker `SIGNAL_TO_PRODUCT_GRAPH_BOUND` after compiling a Product Graph from only those supplied facts.
- When an approved signal lacks requirements or Gherkin acceptance, the system shall return marker `SIGNAL_SPEC_GAPS_EXPOSED` and write a needs-input PRD draft without creating a mission.
- When a mission is created, the system shall return marker `CREATOR_VERIFIER_CONTEXT_WALL` with creator inputs separated from verifier inputs and creator scratchpads forbidden to the verifier.
- If creator and verifier identities are equal, the system shall return marker `VERIFIER_IDENTITY_DISTINCT` with completion validity `false` and shall not write a completion receipt.
- If any completion criterion is missing, duplicated, failed, or lacks bound evidence, the system shall return marker `NO_FINISH_CONTRACT` and shall not write a completion receipt.
- When all criteria pass under an independent verifier, the system shall return marker `VALIDATION_EVIDENCE_BOUND` after writing schema `factory.mission.completion.v1` bound to mission, validation manifest, and evidence hashes.
- When a completion receipt is verified, the system shall return marker `MISSION_COMPLETION_VERIFIED` only if all bound files and hashes remain unchanged.
- The system shall return marker `MODEL_ROUTING_ADVISORY_ONLY` when triage selects abstract creator and verifier reasoning profiles without invoking or purchasing a model.
- When measured outcome evidence is supplied, the system shall return markers `OUTCOME_FEEDBACK_SIGNAL_BOUND` and `SIGNAL_LOOP_REENTERED_LOCAL_ONLY` after binding its hash into a new untrusted local telemetry signal that still requires normal triage and owner approval.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Triage one signal through the Opinion Dock
  Given an owner-supplied signal and a valid Opinion Dock under 2000 lines
  When signal capture and signal triage run
  Then the signal is stored as untrusted local data
  And each priority contribution names the matching dock rule
  And promotion remains blocked pending a Product Owner decision

Scenario: Correct factory taste instead of one output
  Given an Opinion Dock with one active architecture rule
  When its owner records a replacement rule and rationale
  Then the correction history preserves the previous rule hash
  And future triage uses the new active rule

Scenario: Preserve the human product boundary
  Given an approved signal without supplied requirements or Gherkin acceptance
  When signal promotion runs
  Then a needs-input PRD draft records the missing facts
  And no Product Graph mission or deployment action is created

Scenario: Compile a complete approved signal
  Given an approved signal with supplied requirements outcomes and Gherkin acceptance
  When signal promotion runs
  Then the resulting Product Graph binds the signal and owner-decision hashes
  And mission execution still requires a separate approval

Scenario: Reject self-verification and partial proof
  Given a mission with creator-verifier context separation and required criteria
  When the creator is also the verifier or one criterion lacks evidence
  Then completion is rejected with no completion receipt

Scenario: Close only with independent complete evidence
  Given a valid mission and a validation manifest from a distinct verifier
  When every required criterion passes with a local evidence file
  Then the completion receipt binds the mission validation and evidence hashes
  And later evidence drift invalidates completion verification

Scenario: Close the measured feedback loop locally
  Given one mission outcome and a local telemetry evidence file
  When signal feedback runs
  Then a hash-bound untrusted telemetry signal re-enters the queue
  And triage execution and deployment remain unauthorized

Scenario: Every requirement has an observable validator marker
  Given the Signal Loop contract
  When strict validator mutation runs
Then contract markers include `SIGNAL_NORMALIZED_LOCAL_ONLY`, `SIGNAL_PROVENANCE_BOUND`, `SIGNAL_DEDUP_HASHED`, `OPINION_DOCK_BOUND`, `OPINION_DOCK_LINE_BUDGET`, `OPINION_CORRECTION_APPEND_ONLY`, `TRIAGE_EXPLAINABLE`, `HANDS_OFF_RULE_ENFORCED`, `OWNER_DECISION_REQUIRED`, `OWNER_DECISION_BOUND`, `MISSION_EXECUTION_APPROVAL_BOUND`, `SIGNAL_TO_PRODUCT_GRAPH_BOUND`, `SIGNAL_SPEC_GAPS_EXPOSED`, `CREATOR_VERIFIER_CONTEXT_WALL`, `VERIFIER_IDENTITY_DISTINCT`, `NO_FINISH_CONTRACT`, `VALIDATION_EVIDENCE_BOUND`, `MISSION_COMPLETION_VERIFIED`, `MODEL_ROUTING_ADVISORY_ONLY`, `OUTCOME_FEEDBACK_SIGNAL_BOUND`, and `SIGNAL_LOOP_REENTERED_LOCAL_ONLY`
```

## SHOULD - Technical and structural

- ADR references: `adr/0009-signal-loop-and-independent-verification.md`
- Data models: `factory.signal.v1`, `factory.opinion_dock.v1`,
  `factory.signal.triage.v1`, `factory.owner_decision.v1`, and
  `factory.mission.completion.v1`.
- CLI contracts: `factory signal capture|triage|decide|promote|feedback`,
  `factory opinion init|correct|verify`, and
  `factory mission close|verify-completion`.
- Inputs from Slack, GitHub, Sentry, social media, telemetry, or internal
  conversations are untrusted data, not executable instructions.
- Signal IDs, rule hashes, triage hashes, decisions, validation manifests, and
  completion receipts use canonical SHA-256 bindings.
- Routing profiles are abstract labels; provider and model mappings belong to a
  separately approved runtime adapter.

### Authorized bounded constants

- Signal title is at most 240 characters and body is at most 65536 UTF-8 bytes.
- Signal severity is an integer from 1 through 5.
- Opinion Dock rendered JSON is at most 2000 lines.
- Opinion rules are at most 500 entries and each rule statement is at most 1000 characters.
- Creator and verifier IDs are non-empty strings of at most 120 characters.
- Validation manifests contain at most 200 criteria and 100 evidence files.

## SHOULD NOT - Implementation details

- Do not scrape, poll, message, deploy, merge, purchase inference, or enable a schedule.
- Do not treat public availability as connector authorization.
- Do not let triage output become a mission without Product Owner approval.
- Do not expose creator scratchpads, hidden reasoning, or intermediate attempts to the verifier.
- Do not let the same identity create and verify a completion receipt.
- Do not call model selection a measured quality or cost optimization without runtime evidence.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `dock_lines` > 2000 | REJECT_DOCK |
| 2 | `hands_off_matches` > 0 | RECOMMEND_BLOCK |
| 3 | `owner_decision` != approved | BLOCK_PROMOTION |
| 4 | `requirements` == 0 or `acceptance` == 0 | WRITE_NEEDS_INPUT_DRAFT |
| 5 | `creator_id` == `verifier_id` | REJECT_COMPLETION |
| 6 | `missing_criteria` > 0 or `failed_criteria` > 0 | REJECT_COMPLETION |
| 7 | `missing_evidence` > 0 | REJECT_COMPLETION |
| 8 | else | WRITE_BOUND_COMPLETION_RECEIPT |
