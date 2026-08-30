# Spec: enterprise-ops-control-plane-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST — Functional core
### Description
Provide a local-first, portable enterprise operations bundle for teams using
Code Factory with AI coding agents. The bundle gives a team one inspectable
workspace for tenant-scoped evidence, local identity lifecycle, an optionally
isolated proof runner, required-check evaluation, outcome telemetry, SLA
readiness, and one safe golden-path status surface. It never claims that a
process boundary is a kernel sandbox or that proposed support targets are a
live SLA.

### User roles
- `team_operator`: records evidence, executes an explicitly approved proof,
  and reads team status.
- `reviewer`: evaluates required checks, outcomes, and evidence exports.
- `service_owner`: supplies named SLA activation evidence; cannot activate an
  SLA without every gate.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- The system shall create a tenant-bound SQLite evidence workspace and emit `eops_marker=EOPS_EVIDENCE_READY`; the workspace has an append-only hash-linked audit chain and content-addressed evidence records. [REQ-EOPS-EVIDENCE]
- The system shall maintain an identity registry and emit `eops_marker=EOPS_IDENTITY_READY`; records have a stable subject, tenant, role, status, and audit event, and suspended or revoked identities are denied before evidence writes or approvals. [REQ-EOPS-IDENTITY]
- When a proof command is run, the system shall return a validated runner receipt and emit `eops_marker=EOPS_RUNNER_READY`; the request accepts a workspace-contained command vector, timeout between 1 and 3600 seconds, output cap between 1024 and 4194304 bytes, and an isolation backend, while Docker uses a read-only mount, `--network none`, CPU limit 1, memory limit 512 MB, and a local execution backend is labelled `not-isolated`. [REQ-EOPS-RUNNER]
- When changed paths are evaluated, the system shall return a required-check decision and emit `eops_marker=EOPS_CHECK_READY`; the decision names stale or missing proof and never grants merge, deploy, or release authority. [REQ-EOPS-SDLC]
- When an outcome event is recorded, the system shall append a hash-linked event and emit `eops_marker=EOPS_OUTCOME_READY`; the event has actor, service, environment, result, and duration_ms >= 0, and aggregate counts exclude source, prompts, and secrets. [REQ-EOPS-OUTCOMES]
- When SLA readiness is evaluated, the system shall return a report listing each of seven activation gates and emit `eops_marker=EOPS_SLA_READY`; the report returns `PROPOSED` unless all gates have explicit evidence and a signed acceptance record. [REQ-EOPS-SLA]
- The system shall return a status payload from one command and emit `eops_marker=EOPS_GOLDEN_READY`; the payload contains the next safe local action, evidence counts, identity counts, runner posture, required-check state, outcome aggregates, and SLA state without claiming hosted availability. [REQ-EOPS-GOLDEN]
- If a path escapes the workspace, a command is shell text rather than an argv vector, an identity is inactive, evidence is cross-tenant, or a runner backend is unavailable, the system shall return a stable error code before mutation and shall reject the operation without writing a success receipt, and shall emit `marker=EOPS_FAIL_CLOSED`. [REQ-EOPS-FAIL-CLOSED]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Team operator uses the golden path
  Given an initialized tenant workspace and an active team operator
  When the operator records evidence, evaluates required checks, and reads status
  Then the evidence and audit chain verify
  And status returns an actionable next command without release authority

Scenario: Unavailable isolation never masquerades as proof
  Given a proof request that selects Docker on a host without Docker
  When the runner starts
  Then it returns `E_RUNNER_BACKEND_UNAVAILABLE`
  And no passing runner receipt is written

Scenario: SLA remains proposed until every gate is evidenced
  Given an SLA evidence manifest with one missing activation gate
  When readiness is evaluated
  Then the result is `PROPOSED`
  And the missing gate is named

Scenario: Identity lifecycle denies inactive actors
  Given a suspended identity in the tenant registry
  When it attempts an evidence write
  Then the operation returns `E_IDENTITY_INACTIVE`
  And the evidence count does not change

Scenario: Every operations slice has a traceable marker
  Given an initialized operations workspace
  When the seven operations slices are evaluated
  Then the result includes `EOPS_EVIDENCE_READY`
  And the result includes `EOPS_IDENTITY_READY`
  And the result includes `EOPS_RUNNER_READY`
  And the result includes `EOPS_CHECK_READY`
  And the result includes `EOPS_OUTCOME_READY`
  And the result includes `EOPS_SLA_READY`
  And the result includes `EOPS_GOLDEN_READY`
  And the result includes `EOPS_FAIL_CLOSED`
```

## SHOULD — Technical/structural
- ADR references: `docs/ENTERPRISE_1_0.md`, `docs/SUPPORT_SLA.md`.
- Data model: `.factory/ops/evidence.db`, `identities.json`, `outcomes.jsonl`,
  and hash-bound JSON receipts under `.factory/ops/`. Stable errors include
  `E_RUNNER_BACKEND_UNAVAILABLE` and `E_IDENTITY_INACTIVE`; declared facts
  include `identity_active`, `runner_available`, `proof_fresh`, and
  `local_checks_pass`.
- API contract: Python interfaces in `factoryline.enterprise_ops`; CLI under
  `factory ops`.

## SHOULD NOT — Implementation details
<!-- Leave the "how" to the plan/tasks unless it is a systemic invariant -->

## Decision logic (factory candidates)
<!-- Ordered business rules over extracted facts. specline handoff compiles
     these via HSF instead of letting agents improvise them. -->
| # | if | then |
|---|----|------|
| 1 | `identity_active` is false or tenant is cross-boundary | reject before mutation |
| 2 | `runner_available` is false for a requested Docker backend | return backend error; never downgrade silently |
| 3 | `proof_fresh` is false | return `REVIEW_REQUIRED` |
| 4 | an SLA gate lacks explicit evidence | keep status `PROPOSED` |
| 5 | `local_checks_pass` is true | return `READY_FOR_HUMAN_REVIEW` |
