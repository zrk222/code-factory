# Spec: release-decision-cards-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core

### Description

Provide one deterministic, read-only decision card for a named feature release.
The card must distinguish an intentional local stop from a missing or failed
local evidence chain, a release-workflow defect, and an unobserved external
provider gate. It exists for maintainers, connected coding agents, Mission
Control, Graph Ops, MCP clients, and CLI users who need a safe next action
without mistaking a local non-zero exit for a Marketplace or provider rejection.

### User roles

- Maintainer: reads the card and decides whether to repair local evidence or
  inspect an external provider.
- Connected coding agent: reads the structured card but cannot turn it into
  publish, approval, deployment, signing, messaging, credential, or connector
  authority.
- Reviewer: verifies that local evidence is complete while retaining ownership
  of every external decision.

### Requirements (EARS)

- When `CARD_INPUT_VALID` receives a bounded `feature_id`, the system shall return `RELEASE_DECISION_CARD_READ_ONLY`. [R1]
- When `CARD_WORKFLOW_FAILURE` receives `workflow_ok=false`, the system shall return `LOCAL_WORKFLOW_BLOCKED` before feature verification. [R2]
- When `CARD_CONTRACT_ABSENT` receives `workflow_ok=true` and `contract_exists=false`, the system shall return `LOCAL_EVIDENCE_MISSING`. [R3]
- When `CARD_EVIDENCE_FAILURE` receives `workflow_ok=true`, `contract_exists=true`, and `release_ready=false`, the system shall return `LOCAL_EVIDENCE_BLOCKED`. [R4]
- When `CARD_LOCAL_PASS` receives `workflow_ok=true`, `contract_exists=true`, and `release_ready=true`, the system shall return `EXTERNAL_GATES_UNOBSERVED`. [R5]
- If `CARD_INPUT_INVALID` receives an invalid `feature_id` or unsupported MCP argument, the system shall return `RELEASE_DECISION_INPUT_REJECTED`. [R6]
- When `CARD_AUTHORITY_READ` reads a card, the system shall return `DECISION_ZERO_AUTHORITY`. [R7]
- When `CARD_MISSION_RELEASE_FAILURE` reads `workflow_ok=false`, the system shall return `repair_release_workflow` before `repair_evidence_chain`. [R8]
- When `CARD_SURFACE_PARITY` receives `feature_id=payments`, the system shall return `DECISION_SURFACE_PARITY`. [R9]
- When `CARD_NON_EXECUTION_READ` reads a card, the system shall return `DECISION_NON_EXECUTING`. [R10]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: valid input returns a read-only card
  Given CARD_INPUT_VALID receives feature_id=payments
  When a user requests a card
  Then the marker is RELEASE_DECISION_CARD_READ_ONLY

Scenario: static workflow error takes priority
  Given CARD_WORKFLOW_FAILURE returns workflow_ok=false
  When a user requests a card
  Then the state is LOCAL_WORKFLOW_BLOCKED

Scenario: no strict feature contract exists
  Given CARD_CONTRACT_ABSENT returns contract_exists=false
  When a user requests a card
  Then the state is LOCAL_EVIDENCE_MISSING

Scenario: strict local evidence is blocked
  Given CARD_EVIDENCE_FAILURE returns release_ready=false
  When a user requests a card
  Then the state is LOCAL_EVIDENCE_BLOCKED

Scenario: local gates pass without a provider claim
  Given CARD_LOCAL_PASS returns release_ready=true
  When a user requests a card
  Then the state is EXTERNAL_GATES_UNOBSERVED

Scenario: invalid MCP input is rejected
  Given CARD_INPUT_INVALID receives an unsupported MCP argument
  When a connected agent requests a card
  Then the marker is RELEASE_DECISION_INPUT_REJECTED

Scenario: card authority is always zero
  Given CARD_AUTHORITY_READ reads a card
  When a connected agent requests a card
  Then the marker is DECISION_ZERO_AUTHORITY

Scenario: Mission Control prioritizes a release workflow defect
  Given CARD_MISSION_RELEASE_FAILURE returns workflow_ok=false
  When Mission Control reads a workspace
  Then the next action is repair_release_workflow

Scenario: CLI and MCP agree on one feature
  Given CARD_SURFACE_PARITY receives feature_id=payments
  When CLI and MCP request a card
  Then the marker is DECISION_SURFACE_PARITY

Scenario: card evaluation does not execute an action
  Given CARD_NON_EXECUTION_READ reads a card
  When a user requests a card
  Then the marker is DECISION_NON_EXECUTING
```

## SHOULD — Technical/structural

- ADR references: existing release-contract, release-integrity, verification,
  Mission Control, and MCP authority boundaries.
- Data model: pure JSON-compatible card with `feature_id`, `state`, `classification`, `workflow_integrity`, `local_evidence`, `blockers`, `external_gates`, `next_action`, `authority`, and `claim_boundary`; declared facts are `feature_id`, `workflow_ok`, `contract_exists`, `contract_path`, `release_ready`, `provider_contacted`, `execution`, `approval`, `repair`, `merge`, `publication`, `deployment`, `signing`, `messaging`, `credential`, `connector`, `filesystem_write`, `provider_call`, `process_execution`, `credential_access`, and `connector_access`; feature identifiers use lowercase ASCII letters, digits, dot, underscore, and hyphen and are at most 64 characters.
- API contract: source CLI `factory release decision payments --root . --json`; MCP `factory.release_decision` with exactly one `feature` string input.
- Deterministic ordering: workflow blockers first in release-integrity order,
  then feature blockers ordered by source, code, and detail.
- Reuse `release_integrity()` and strict `verify_feature()`; do not duplicate
  release policy or invent provider observations.

## SHOULD NOT — Implementation details

- Do not contact external marketplaces, repositories, credential stores, or
  providers.
- Do not mutate receipt, contract, workflow, cache, status, or provider state.
- Do not infer an external rejection from a local gate, an unavailable
  contract, or an incomplete receipt.
- Do not make the card a release command or an automatic repair loop.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `workflow_ok=false` | `LOCAL_WORKFLOW_BLOCKED`; list workflow checks; `repair_release_workflow` |
| 2 | `workflow_ok=true` and `contract_exists=false` | `LOCAL_EVIDENCE_MISSING`; identify `contract_path`; `create_or_restore_release_contract` |
| 3 | `workflow_ok=true`, `contract_exists=true`, and `release_ready=false` | `LOCAL_EVIDENCE_BLOCKED`; preserve normalized local blockers; `repair_local_evidence_chain` |
| 4 | `workflow_ok=true`, `contract_exists=true`, and `release_ready=true` | `EXTERNAL_GATES_UNOBSERVED`; `provider_contacted=false` |
