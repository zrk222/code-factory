# Spec: agent-cloud-incident-readiness-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Add supervised incident containment and recovery rehearsal to the local Convex pilot. Opening an incident must stop new agent work, close pending authority, roll back an active canary, preserve evidence, and require five distinct recovery checks before an operator can resume service. This does not claim production incident response, hosted identity, or multi-tenancy.

### Requirements (EARS)

- When an Operator opens an incident, the system shall return `INCIDENT_CONTAINED` after creating exactly 1 contained incident and appending incident receipt and audit evidence.
- When an incident is contained, the system shall return `INCIDENT_AUTHORITY_CLOSED` after suspending an active agent, blocking every awaiting-approval run, and rejecting every pending approval.
- When an incident is contained, the system shall return `INCIDENT_CANARY_ROLLED_BACK` after rolling back every active canary.
- If an open incident already exists for the agent, the system shall return `E_INCIDENT_ACTIVE` before any write.
- When an Operator records one declared recovery check, the system shall return `RECOVERY_CHECK_RECORDED` after appending exactly 1 unique check.
- If the same recovery check already exists for the incident, the system shall return `E_RECOVERY_CHECK_DUPLICATE` before any write.
- If fewer than exactly 5 distinct recovery checks exist, the system shall return `E_RECOVERY_INCOMPLETE` before resolving or resuming the agent.
- When exactly 5 declared recovery checks exist and the incident is contained, the system shall return `INCIDENT_RESOLVED` after marking the incident resolved, resuming a suspended agent, and appending recovery receipt and audit evidence.
- When the incident surface renders, the system shall return `INCIDENT_RUNBOOK_VISIBLE` after showing severity, containment outcomes, exactly 5 recovery checks, evidence state, and the resolve control.
- When the incident surface renders at 390 and 1440 CSS pixels, the system shall return `INCIDENT_UI_RESPONSIVE` after exposing containment and recovery controls without horizontal overflow or overlapping actions.
- The system shall return `CONVEX_ONLY_STACK` after proving Convex is the only application backend.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Contain an active incident
  Given 1 active agent 1 awaiting-approval run 1 pending approval and 1 active canary
  When the Operator opens a sev1 incident
  Then INCIDENT_CONTAINED suspends the agent blocks exactly 1 run rejects exactly 1 approval rolls back exactly 1 canary and appends evidence

Scenario: Reject duplicate incident and duplicate recovery check
  Given 1 contained incident
  When another incident or an existing recovery check is submitted
  Then E_INCIDENT_ACTIVE or E_RECOVERY_CHECK_DUPLICATE is returned before writes

Scenario: Require the complete recovery runbook
  Given 1 contained incident with fewer than 5 distinct recovery checks
  When the Operator requests resolution
  Then E_RECOVERY_INCOMPLETE is returned and the agent remains suspended

Scenario: Resolve after an exercised runbook
  Given 1 contained incident with exactly 5 distinct recovery checks
  When the Operator resolves it
  Then INCIDENT_RESOLVED resumes the suspended agent and appends recovery evidence

Scenario: Render incident readiness
  Given incident and recovery history
  When the safety surface renders at 390 and 1440 CSS pixels
  Then INCIDENT_RUNBOOK_VISIBLE shows containment exactly 5 checks and resolution state
  And INCIDENT_UI_RESPONSIVE proves 0 horizontal overflow and 0 overlapping actions
```

## SHOULD - Technical/structural

- ADR reference: `adr/agent-cloud-incident-readiness-v1.md`.
- Convex API: `products/agent-cloud/app/convex/incidents.ts`.
- UI: `products/agent-cloud/app/src/components/IncidentResponsePanel.tsx`.

### Authorized bounded constants

- Severity is exactly `sev1` or `sev2`; incident status is exactly `contained` or `resolved`.
- Recovery checks are exactly `containment-verified`, `evidence-preserved`, `root-cause-recorded`, `rollback-verified`, and `owner-approved`.
- Resolution requires exactly 5 distinct checks; summaries and resolution notes are 1 through 500 characters.
- Browser widths are 390 and 1440 CSS pixels; icon sizes are 15, 16, 17, 18, 20, 21, 22, 24, 26, and 27 CSS pixels.
- Existing typography weights are 400, 500, 600, 700, and 800; `PROOF LINE 01` remains authorized.
- The existing release-safety surface retains deterministic gate count 6, model threshold 80, default model score 88, traffic bounds 5 through 25, default traffic 10, promotion observation count 20, and percentage display cap 100.
- Test and browser commands time out after 120 seconds.

## SHOULD NOT - Implementation details

- No autonomous resolution, production paging, external notification, hosted multi-tenancy, OIDC, or billing claim.
- No deletion of receipts, audit events, or incident history.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `INCIDENT_CONTAINED` exists | create exactly 1 contained incident and append incident receipt and audit evidence |
| 2 | `E_INCIDENT_ACTIVE` exists | add exactly 0 incident records |
| 3 | `RECOVERY_CHECK_RECORDED` is absent after check request | block check success |
| 4 | `E_RECOVERY_CHECK_DUPLICATE` exists | add exactly 0 recovery checks |
| 5 | `E_RECOVERY_INCOMPLETE` exists | keep agent suspended and incident contained |
| 6 | `INCIDENT_RESOLVED` exists | resume only a suspended agent and append recovery evidence |
| 7 | `INCIDENT_RUNBOOK_VISIBLE` is absent | block UI release |
| 8 | `INCIDENT_UI_RESPONSIVE` is absent | block UI release |
| 9 | `CONVEX_ONLY_STACK` is absent | block release |
| 10 | `INCIDENT_CONTAINED` is absent after `sev1` or `sev2` open request | block incident success |
| 11 | `INCIDENT_AUTHORITY_CLOSED` is absent | block incident success |
| 12 | `INCIDENT_CANARY_ROLLED_BACK` is absent | block incident success |
