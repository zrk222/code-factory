# Spec: proof-review-workflow-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Turn the existing Continuous Proof Operations coordinator into one approachable, agent-neutral review workflow. A developer can seal intent, capture an agent trajectory, assess a change, preserve a confirmed failure as a regression capsule, inspect a team inbox, and export an offline-verifiable proof card without granting Code Factory execution or approval authority.

### User roles

- Developer: confirms intent and supplies local evidence.
- Reviewer: owns final approval and regression promotion.
- Agent or harness: may emit events and receipts but cannot grade itself or authorize outcomes.

### Declared facts

- `intent_contract_valid`: every required intent field is present, the named confirmer is present, and the digest matches.
- `execution_evidence_state`: exactly missing, current_passed, current_failed, stale, or invalid.
- `scope_state`: exactly contained or escaped.
- `judgment_state`: exactly routine or consequential.
- `repair_state`: exactly absent, awaiting_reverification, or reverified.
- `binding_state`: exactly current, stale, conflicting, or invalid.
- `independent_audit_present`: whether the terminal trajectory event was authored by an actor different from the worker.
- `human_confirmation_present`: whether a named human confirmed regression promotion.
- `proof_card_integrity_valid`: whether the proof-card canonical digest matches.

### Requirements (EARS)

- The system shall reject a contract unless the outcome, at least one acceptance condition, at least one rejection condition, at least one validator, at least one allowed path, and one named human confirmer are present; otherwise it shall emit `INTENT_CONTRACT_CONFIRMED` with a SHA-256-bound intent contract. (REQ-PR-001)
- When the system validates the named-human-confirmed intent contract, the system shall emit `FIVE_MINUTE_PROOF_REVIEW_RECORDED`, join the contract with the existing Continuous Proof record, and return exactly one route: `evidence_required`, `human_required`, `reverification_required`, or `review_ready`. (REQ-PR-002)
- The system shall emit `AGENT_HOOK_PACK_WRITTEN` with five non-secret repository-local hook templates for GitHub Copilot, Claude Code, Codex, Cursor, and generic JSONL without modifying vendor configuration files. (REQ-PR-003)
- When the system receives a named human confirmation for a current verified proof-review record with a causal failure, the system shall emit `REGRESSION_CAPSULE_PROMOTED` after storing one immutable regression capsule preserving the causal receipt digest. (REQ-PR-004)
- The system shall emit `TEAM_PROOF_INBOX_READ_ONLY` after inspecting at most 500 proof-review records, separating current, stale, and invalid records, sorting `human_required` before the other three routes, and returning no inferred user, effort, savings, or productivity value. (REQ-PR-005)
- The system shall reject a trajectory exceeding 500 events or 1 MiB and shall emit `AGENT_TRAJECTORY_PROVED` after validating ordered required events, allowed tools, forbidden tools, scope paths, and `independent_audit_present`. (REQ-PR-006)
- The system shall emit `SHAREABLE_PROOF_CARD_EXPORTED` after exporting public-safe JSON, Markdown, and SVG proof cards whose canonical digest is verifiable offline and whose status never implies approval, merge, deployment, compliance, or production readiness. (REQ-PR-007)
- When Graph Ops builds a snapshot, the system shall emit `GRAPH_OPS_PROOF_REVIEW_READ_ONLY`, return bounded read-only proof-review counts and one next team-review item, and leave authoritative proof receipts unchanged. (REQ-PR-008)
- The system shall emit `PROOF_REVIEW_PATH_REJECTED` when a path escapes the selected workspace, reject any input larger than 1 MiB, write accepted artifacts atomically, and emit no credential, prompt, log, source-body, or network field. (REQ-PR-009)
- The system shall return the existing exit codes and emit the existing `CONTINUOUS_PROOF_HISTORY_READ_ONLY` receipt schema when the `factory first-proof`, `factory wrap`, and `factory proof-ops` regression tests execute. (REQ-PR-010)

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Intent must be complete and confirmed
  Given an intent draft missing a rejection condition
  When the contract builder evaluates it
  Then the contract is rejected

Scenario: Five minute review remains fail closed
  Given intent_contract_valid is true and changed bytes exist
  When independent observed evidence is absent
  Then FIVE_MINUTE_PROOF_REVIEW_RECORDED returns the route evidence_required
  And final approval remains false

Scenario: Worker evidence cannot self approve
  Given an agent trajectory without an independent audit event
  When trajectory proof evaluates the trace
  Then the trajectory proof fails

Scenario: Human confirms regression promotion
  Given human_confirmation_present is true and a current verified proof-review record has a causal failure
  When a named reviewer confirms promotion
  Then REGRESSION_CAPSULE_PROMOTED binds an immutable regression capsule to the proof-review digest

Scenario: Proof card detects tampering
  Given an offline-verifiable proof card
  When one card byte changes
  Then offline verification fails

Scenario: Every requirement has an observable validator marker
  Given the proof-review workflow contract
  When strict validator mutation runs
  Then markers include `INTENT_CONTRACT_CONFIRMED`, `FIVE_MINUTE_PROOF_REVIEW_RECORDED`, `AGENT_HOOK_PACK_WRITTEN`, `REGRESSION_CAPSULE_PROMOTED`, `TEAM_PROOF_INBOX_READ_ONLY`, `AGENT_TRAJECTORY_PROVED`, `SHAREABLE_PROOF_CARD_EXPORTED`, `GRAPH_OPS_PROOF_REVIEW_READ_ONLY`, `PROOF_REVIEW_PATH_REJECTED`, and `CONTINUOUS_PROOF_HISTORY_READ_ONLY`
```

## SHOULD - Technical/structural

- Use the existing Continuous Proof coordinator as the authoritative change-evidence record.
- Store workflow artifacts below `.factory/proof-review/`.
- Expose one `factory proof-review` command family.

## SHOULD NOT - Non-goals

- Execute an agent or validator.
- Apply a repair.
- Approve, commit, merge, publish, deploy, sign, message, access credentials, or authorize a connector.
- Claim unique users, time saved, token saved, quality, security, compliance, or production readiness.
- Automatically promote a failure without a named human confirmation.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `intent_contract_valid` is false | reject contract creation |
| 1a | `intent_contract_valid` is true | emit `FIVE_MINUTE_PROOF_REVIEW_RECORDED` and evaluate one closed route |
| 2 | `execution_evidence_state` is missing | route `evidence_required` |
| 3 | `scope_state` is escaped, `execution_evidence_state` is current_failed, or `judgment_state` is consequential | route `human_required` |
| 4 | `repair_state` is awaiting_reverification | route `reverification_required` |
| 5 | `binding_state` is current, `execution_evidence_state` is current_passed, and `repair_state` is absent or reverified | route `review_ready` while final approval remains false |
| 6 | `independent_audit_present` is false | fail trajectory proof |
| 7 | `human_confirmation_present` is false | reject regression promotion |
| 7a | `human_confirmation_present` is true and `binding_state` is current | emit `REGRESSION_CAPSULE_PROMOTED` only for a current causal failure |
| 8 | `proof_card_integrity_valid` is false | fail offline verification |
