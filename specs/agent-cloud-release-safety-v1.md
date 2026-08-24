# Spec: agent-cloud-release-safety-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Add a supervised local release-safety lane to the Convex pilot: model changes require re-evaluation, start as bounded canaries, and either promote or roll back with receipt-bearing evidence. This does not claim production deployment, multi-tenancy, billing, or hosted identity.

### Requirements (EARS)

- When an Operator starts a canary, the system shall return `CANARY_STARTED` only after finding the target AgentSpec version, receiving exactly 6 deterministic gates passed, receiving a model score from 80 through 100, and bounding traffic from 5 through 25 percent.
- If deterministic gates are not exactly 6 or model score is below 80, the system shall return `E_REEVALUATION_REQUIRED` before any write.
- If another canary is active for the agent, the system shall return `E_CANARY_ACTIVE` before any write.
- When an Operator records a canary observation, the system shall return `CANARY_OBSERVATION_RECORDED` after incrementing exactly 1 observation and at most 1 failure.
- When an Operator promotes a canary, the system shall return `CANARY_PROMOTED` only when at least 20 observations and exactly 0 failures exist.
- If promotion evidence is insufficient, the system shall return `E_CANARY_NOT_READY` before any write.
- When an Operator rolls back a canary, the system shall return `CANARY_ROLLED_BACK` after marking the canary rolled back and appending receipt and audit evidence.
- When the release-safety surface renders, the system shall return `RELEASE_SAFETY_VISIBLE` after showing evaluation evidence, traffic bound, observations, failures, promotion readiness, and rollback.
- The system shall return `CONVEX_ONLY_STACK` after proving Convex is the only application backend.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Start a bounded evaluated canary
  Given AgentSpec version 1 and no active canary
  When 6 deterministic gates pass with model score 88 and traffic 10 percent
  Then CANARY_STARTED records the evaluation and bounded traffic

Scenario: Reject unproven release
  Given no active canary
  When 5 deterministic gates pass or model score is 79
  Then E_REEVALUATION_REQUIRED is returned and 0 release records are added

Scenario: Promote only healthy evidence
  Given 1 active canary with 20 observations and 0 failures
  When the Operator promotes it
  Then CANARY_PROMOTED appends receipt and audit evidence

Scenario: Roll back a canary
  Given 1 active canary
  When the Operator rolls it back with a reason
  Then CANARY_ROLLED_BACK appends receipt and audit evidence

Scenario: Render release safety
  Given an AgentSpec and release history
  When the release-safety surface renders at 390 and 1440 CSS pixels
  Then RELEASE_SAFETY_VISIBLE exposes start observe promote and rollback controls without horizontal overflow
```

## SHOULD - Technical/structural

- ADR reference: `adr/agent-cloud-release-safety-v1.md`.
- Convex API: `products/agent-cloud/app/convex/releases.ts`.
- UI: `products/agent-cloud/app/src/components/ReleaseSafetyPanel.tsx`.

### Authorized bounded constants

- Deterministic gate count is exactly 6; model score is 80 through 100; traffic is 5 through 25 percent.
- Promotion requires at least 20 observations and exactly 0 failures.
- Reasons are 1 through 500 characters; browser widths are 390 and 1440 CSS pixels.
- Prototype digests are 16 lowercase hexadecimal characters; test commands time out after 120 seconds.
- Test controls may use model scores 84, 88, and 91, and 19 healthy observations before the twentieth observation.
- Release controls use icon sizes 16, 17, and 26 CSS pixels; the existing shared shell retains icon sizes 15, 18, 20, 21, 22, 24, and 27 CSS pixels and `PROOF LINE 01`.
- The existing visual contract retains typography weights 400, 500, 600, 700, and 800.

## SHOULD NOT - Implementation details

- No production deployment, hosted multi-tenancy, OIDC, billing, provider invocation, or autonomous promotion.
- No promotion without the declared observation and failure bounds.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `CANARY_STARTED` is absent after start request | return `E_REEVALUATION_REQUIRED` before writes |
| 2 | `E_CANARY_ACTIVE` exists | add exactly 0 release records |
| 3 | `CANARY_PROMOTED` is absent after promotion request | return `E_CANARY_NOT_READY` before writes |
| 4 | `CANARY_ROLLED_BACK` exists | append receipt and audit evidence |
| 5 | `CONVEX_ONLY_STACK` is absent | block release |
| 6 | `CANARY_OBSERVATION_RECORDED` is absent after observation request | block observation success |
| 7 | `E_CANARY_NOT_READY` exists | add exactly 0 promotion receipts |
