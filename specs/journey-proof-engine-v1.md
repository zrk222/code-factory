# Spec: journey-proof-engine-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core
### Description
Provide one local, provider-neutral Journey Proof Engine that deterministically compares declared product journeys with observed runtime journeys, packages one runtime failure into a hash-bound capsule, proves producer/consumer and cleanup state across multi-step workflows, and admits a proposed test repair only after a positive execution and an adversarial negative execution. The engine is for developers and reviewers using Code Factory with any browser, API, CI, or external test runner.

### User roles
- Developer: supplies workspace-contained manifests, artifacts, and explicit argv commands.
- Reviewer: inspects receipts, graphs, capsule context, and healing evidence before deciding whether to promote a change.
- External runner: produces observations and artifacts but receives no Code Factory authority.

### Declared facts
- `input_contract_valid`: whether schema, exact field set, bounds, workspace paths, and bound SHA-256 values verify.
- `journey_sets_equal`: whether declared and observed state, transition, requirement, and outcome sets are identical.
- `workflow_acyclic`: whether the declared test dependency graph has no directed cycle.
- `workflow_values_valid`: whether every consumed value has exactly one earlier producer and equal produced and consumed SHA-256 values.
- `workflow_cleanup_valid`: whether every created side effect has a passed cleanup result at a strictly greater execution index and every cleanup idempotency probe passed.
- `healing_scope_valid`: whether every changed path is workspace-contained and inside the declared allowlist.
- `semantic_identity_valid`: whether role, label, route, and state anchors are non-empty and exactly equal before and after the selector repair.
- `coverage_preserved`: whether every journey ID covered before the repair remains covered after the repair.
- `review_mode_valid`: whether review mode is exactly `human_controlled` or `supervised_auto`, human mode declares no agent command, and auto mode supplies one bounded agent contract.
- `agent_scope_valid`: whether every optional auto-mode agent attempt changed only allowlisted workspace paths.
- `agent_command_exit_zero`: whether the optional auto-mode agent command stayed inside its attempt ceiling from 1 through 3 and timeout ceiling from 1 through 900 seconds and exited zero.
- `agent_audit_valid`: whether the FactoryLine-authored post-run audit binds the declared agent identity, agent argv digest, before/after workspace digests, exact changed paths, scope verdict, positive result, negative mutation result, one closed audit outcome, and a closed FailureClass when the outcome failed, without worker-authored approval.
- `positive_exit_zero`: whether the explicit positive argv command exits 0.
- `negative_exit_nonzero`: whether the explicit negative mutation argv command exits with any non-zero code.

### Requirements (EARS)
- The system shall accept five versioned JSON input schemas with `JOURNEY_INPUT_ACCEPTED`: `factory.journey-declaration.v1`, `factory.journey-observation.v1`, `factory.failure-capsule-input.v1`, `factory.stateful-workflow-input.v1`, and `factory.proof-gated-healing-input.v1`; each command shall reject unknown fields with `JOURNEY_INPUT_REJECTED`.
- When a journey declaration and observation are supplied, the system shall return every missing or unexpected normalized state ID, transition ID, requirement ID, outcome ID, and stale SHA-256-bound artifact with `JOURNEY_REALITY_REVIEW_REQUIRED` and without model inference.
- When a failed runtime input is supplied, the system shall preserve the failed step plus at most one preceding and one following step, bind every referenced artifact by SHA-256, keep classification separate from hypothesis and suggested repair, and emit JSON plus Markdown with `FAILURE_CAPSULE_BOUND`.
- When a stateful workflow input is supplied, the system shall return whether the producer/consumer graph is acyclic, produced and consumed value hashes are identical, every execution result passed, every created side effect has a passed cleanup at a strictly greater execution index, and every cleanup node has a passed idempotency probe; a passing result shall include `WORKFLOW_PROOF_PASSED`.
- When a proof-gated healing input is supplied, the system shall bind a candidate patch, reject changed paths outside the declared allowlist, require identical non-empty semantic anchors before and after the proposed selector change, require preserved journey coverage, execute one explicit positive argv command, execute one explicit negative argv command, and pass only when the positive exits zero and the negative exits non-zero with `HEALING_PROOF_ADMISSIBLE`.
- The system shall return `HEALING_HUMAN_REVIEW_REQUIRED` after proof when review mode is human_controlled, and shall reject an agent command in that mode with HEALING_REVIEW_MODE_INVALID.
- The system shall return `HEALING_AUTO_AWAITING_PROMOTION` after proof when review mode is supervised_auto, execute at most 3 explicit no-shell agent argv attempts inside the workspace, compare workspace file hashes before and after every attempt, reject any changed path outside the allowlist with HEALING_AGENT_SCOPE_ESCAPE, return HEALING_AGENT_FAILED when the final bounded agent command exits non-zero, and withhold final approval.
- When a supervised-auto agent command finishes or is stopped, FactoryLine shall emit one `AGENT_WORK_AUDITED` receipt that binds agent identity, command digest, before and after workspace digests, exact changed paths, scope result, positive result, negative mutation result, one closed audit outcome, and a closed FailureClass for a failed outcome; if the audit cannot verify those facts, the healing decision shall be rejected with `HEALING_AGENT_AUDIT_FAILED`.
- If any input path escapes the workspace, any artifact hash is stale, any graph is cyclic, any state value has no unique producer, any cleanup is missing, any coverage is lost, or any healing negative command exits zero, the system shall fail closed, shall include `WORKFLOW_CLEANUP_MISSING` or `HOLLOW_HEALING_PROOF` when applicable, and shall not issue an admissible receipt.
- The system shall expose verified Journey Proof receipts through Graph Ops and a read-only MCP status tool with `JOURNEY_STATUS_READ_ONLY` and without executing a provider, applying a patch, approving a repair, merging, publishing, deploying, signing, messaging, accessing credentials, or granting a connector.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Exact versioned JSON schemas reject unknown fields
  Given each of the 5 versioned JSON input schemas contains its exact supported field set
  When an unknown field is added to any input
  Then input_contract_valid is false
  And no trusted receipt is written
  And the error is JOURNEY_INPUT_REJECTED

Scenario: Exact versioned JSON schemas are accepted
  Given each of the 5 versioned JSON input schemas contains its exact supported field set
  When the matching Journey Proof command validates the input
  Then input_contract_valid is true
  And the marker is JOURNEY_INPUT_ACCEPTED

Scenario: Reality graph exposes declared and observed drift
  Given one declaration with 3 states, 2 transitions, 2 requirements, and 1 outcome
  And one observation missing 1 transition and containing 1 unexpected state
  When the developer compiles the Journey Reality Graph
  Then the receipt reports exactly 1 missing transition and exactly 1 unexpected state
  And the receipt decision is review_required
  And the returned deltas name normalized state IDs, transition IDs, requirement IDs, outcome IDs, and stale artifact hashes
  And the marker is JOURNEY_REALITY_REVIEW_REQUIRED

Scenario: Failure capsule preserves bounded adjacent evidence
  Given a failed run with 5 ordered steps and failed step index 2
  When the developer creates a Rich Failure Capsule
  Then the capsule contains exactly steps 1, 2, and 3
  And every attached artifact is workspace-contained and SHA-256 verified
  And the hypothesis remains labeled unverified
  And JSON and Markdown capsule artifacts are emitted
  And the marker is FAILURE_CAPSULE_BOUND

Scenario: Stateful workflow rejects an orphaned side effect
  Given a passed producer and consumer workflow that creates 1 side effect
  And no later passed cleanup result exists for that side effect
  When the developer verifies Stateful Workflow Proof
  Then the decision is failed
  And the receipt contains the code WORKFLOW_CLEANUP_MISSING
  And the receipt reports workflow_acyclic, workflow_values_valid, and workflow_cleanup_valid

Scenario: Stateful workflow passes complete value and cleanup proof
  Given every consumed hash has exactly one earlier matching producer
  And every created side effect has a later passed idempotent cleanup
  When the developer verifies Stateful Workflow Proof
  Then the marker is WORKFLOW_PROOF_PASSED

Scenario: Healing rejects a hollow repaired test
  Given a workspace-contained candidate patch with allowed test paths
  And identical semantic anchors and preserved journey coverage
  And the positive command exits 0
  And the negative mutation command exits 0
  When the developer verifies Proof-Gated Healing
  Then the command exits non-zero
  And the receipt contains the marker HOLLOW_HEALING_PROOF

Scenario: Healing admits a challenged repair
  Given a workspace-contained candidate patch with allowed test paths
  And identical semantic anchors and preserved journey coverage
  And the positive command exits 0
  And the negative mutation command exits non-zero
  When the developer verifies Proof-Gated Healing
  Then the receipt decision is admissible_for_human_review
  And the marker is HEALING_PROOF_ADMISSIBLE
  And every repair, approval, merge, publication, deployment, signing, messaging, credential, and connector authority flag is false

Scenario: Human review mode retains final approval
  Given review_mode is human_controlled
  And no agent command is declared
  When Proof-Gated Healing passes its positive and negative checks
  Then the marker is HEALING_HUMAN_REVIEW_REQUIRED
  And final approval remains false

Scenario: Human review mode rejects an agent command
  Given review_mode is human_controlled
  And one agent command is declared
  When Proof-Gated Healing validates review_mode
  Then review_mode_valid is false
  And the marker is HEALING_REVIEW_MODE_INVALID

Scenario: Supervised auto mode rejects an agent scope escape
  Given review_mode is supervised_auto
  And the bounded agent command changes one path outside its allowlist
  When Code Factory compares workspace hashes after the first agent attempt
  Then agent_scope_valid is false
  And the marker is HEALING_AGENT_SCOPE_ESCAPE
  And no second agent attempt executes

Scenario: Supervised auto mode reports bounded agent failure
  Given review_mode is supervised_auto
  And every attempted changed path remains inside the allowlist
  When the final bounded agent command exits non-zero
  Then agent_command_exit_zero is false
  And the marker is HEALING_AGENT_FAILED

Scenario: Supervised auto mode completes without self-approval
  Given review_mode is supervised_auto
  And the bounded agent command exits 0 inside its allowlist
  When the positive test exits 0 and the negative mutation exits non-zero
  Then the marker is HEALING_AUTO_AWAITING_PROMOTION
  And final approval remains false

Scenario: FactoryLine audits the autonomous worker
  Given a supervised-auto agent attempt has stopped
  When FactoryLine records the post-run agent audit
  Then the marker is AGENT_WORK_AUDITED
  And the audit binds agent identity, command digest, before and after workspace digests, exact changed paths, scope result, positive result, negative mutation result, one closed audit outcome, and a closed FailureClass for a failed outcome
  And the worker cannot set approval true

Scenario: Missing autonomous audit blocks healing
  Given review_mode is supervised_auto
  And the post-run agent facts cannot be verified
  When Proof-Gated Healing computes its decision
  Then agent_audit_valid is false
  And the marker is HEALING_AGENT_AUDIT_FAILED

Scenario: Graph Ops and MCP remain read only
  Given one verified Journey Proof receipt
  When Graph Ops and the MCP status tool project that receipt
  Then both projections report the same receipt SHA-256 and decision
  And the marker is JOURNEY_STATUS_READ_ONLY
  And neither projection executes a provider, applies a patch, approves a repair, merges, publishes, deploys, signs, messages, accesses credentials, or grants a connector
```

## SHOULD - Technical/structural
- ADR references: `docs/JOURNEY_PROOF_ENGINE.md`
- Data model: canonical JSON receipts under `.factory/journey-proof/` with explicit schemas and all-false authority maps.
- Receipt persistence: successful commands write atomically below `.factory/journey-proof/`, include `JOURNEY_RECEIPT_WRITTEN`, and hash canonical decision facts so identical inputs and command outcomes remain byte-stable.
- API contract: Python functions and `factory journey reality|capsule|workflow-proof|heal-verify|status` CLI commands; MCP exposes status only.

## SHOULD NOT - Implementation details
- Do not call TestSprite or any provider API.
- Do not store raw secrets or unbounded logs in receipts.
- Do not treat observed behavior as approved intent.
- Do not auto-apply a healing patch or infer that a passing receipt authorizes release.
- Do not present a model-authored hypothesis as a verified root cause.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | `input_contract_valid` is false | reject without a trusted receipt |
| 2 | `journey_sets_equal` is false | emit review_required with exact deterministic deltas |
| 3 | `workflow_acyclic`, `workflow_values_valid`, or `workflow_cleanup_valid` is false | emit failed with closed reason codes |
| 4 | `review_mode_valid` is false | emit HEALING_REVIEW_MODE_INVALID |
| 5 | `agent_scope_valid` is false | emit HEALING_AGENT_SCOPE_ESCAPE |
| 6 | `agent_command_exit_zero` is false | emit HEALING_AGENT_FAILED |
| 7 | `agent_audit_valid` is false | emit HEALING_AGENT_AUDIT_FAILED |
| 8 | `healing_scope_valid`, `semantic_identity_valid`, or `coverage_preserved` is false | emit HEALING_PRECHECK_REJECTED |
| 9 | `positive_exit_zero` is false | emit HEALING_POSITIVE_FAILED |
| 10 | `negative_exit_nonzero` is false | emit HOLLOW_HEALING_PROOF |
| 11 | every healing fact is true | emit admissible_for_human_review |
