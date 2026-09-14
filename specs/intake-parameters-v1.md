# Spec: intake-parameters-v1

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

The Intake Parameter Envelope shall bind bounded operating parameters to a
verified named-human intake confirmation without granting execution or release
authority.

### Declared facts

- `request_schema`: `factory.intake-parameters-request.v1` has exactly seven
  top-level fields: confirmation, parameters, provenance, approver, expiry, and rationale.
- `parameters`: mode, risk, four mission budgets, scope paths, the canonical six
  runtime-audit lanes, and external-effects posture.
- `provenance`: every parameter group has one of four origins; only
  `human_confirmed` and `trusted_source` are authoritative.
- `bounds`: mission values never exceed `MISSION_MAXIMA`; scope is 1..64 safe
  workspace-relative paths; expiry is future and no more than 30 days.
- `authority`: implementation, execution, external effects, publication, and
  deployment remain `not_authorized`.
- `intake_parameters`: the sealed envelope and its `parameters`/`provenance`
  objects are the bounded data model surfaced by this slice.
- `blocked`: a verification state returned when the envelope fails integrity,
  expiry, or source-binding checks; `INTAKE_PARAMETERS_DRIFT` is its marker.
- `intake_parameters_drift`: the exact fail-closed verification marker for a
  changed or invalid envelope.

### Requirements (EARS)

- When a request binds to a current verified intake confirmation with complete six-lane coverage, bounded values, and authoritative provenance, sealing shall return `READY` and a self-hash-verified receipt.
- If an agent proposes any value, sealing shall return `REVIEW_REQUIRED` and shall mark that value advisory rather than authoritative.
- If a request contains unknown fields, traversal, symlinks, secrets, duplicate scope, invalid budgets, incomplete lanes, mismatched effects, expiry, or changed hashes, sealing shall reject it with a stable `INTAKE_PARAMETERS_*` code and shall write no ready receipt.
- If autonomous mode is requested without local-only effects and authoritative provenance for every group, the system shall reject it with `INTAKE_PARAMETERS_AUTONOMY_REJECTED`.
- When status is read, Mission Control, Graph Ops, MCP, WebMCP, and the Junie taxonomy shall return bounded metadata and one explicit next action.

## SHOULD NOT - Non-goals

- No worker execution, model/provider call, credential access, repair, merge,
  publication, deployment, or approval.
- No semantic claim that a parameter value is correct merely because it is
  human-confirmed; independent audit lanes still supply the proof.

## Acceptance criteria

```gherkin
Scenario: Seal an authoritative envelope
  Given a verified human intake confirmation and complete bounded parameters
  When the owner seals the request
  Then the receipt returns READY and contains a valid parameter_sha256

Scenario: Keep agent proposals advisory
  Given one parameter group has origin agent_proposed
  When the owner seals the request
  Then the receipt returns REVIEW_REQUIRED and authoritative is false

Scenario: Refuse a weakened intake
  Given a request omits one canonical audit lane or widens a mission budget
  When the owner seals the request
  Then the request is rejected with an INTAKE_PARAMETERS error

Scenario: Surface drift
  Given a sealed receipt whose request or confirmation source changed
  When the owner verifies the receipt
  Then verification returns BLOCKED with INTAKE_PARAMETERS_DRIFT
```
