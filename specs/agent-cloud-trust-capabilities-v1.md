# Spec: agent-cloud-trust-capabilities-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Add supervised execution-time authorization to the local Convex PR Assurance pilot. A capability is a short-lived local database record, not a signed bearer token. It binds one approved run action to subject, audience, scope, resource, environment, policy, expiry, one-use replay state, and maximum cost. Authorization reserves spend atomically but invokes no connector.

### Requirements (EARS)

- When an independently approved run requests a capability, the system shall return `CAPABILITY_ISSUED`, `CAPABILITY_SHORT_LIVED`, and `CAPABILITY_APPROVAL_BOUND` after creating exactly 1 active grant with a lifetime from 30 through 900 seconds.
- If approval is absent or rejected, the system shall return `E_CAPABILITY_APPROVAL_REQUIRED` before writing a grant; if its digest differs by at least 1 character the system shall return `E_CAPABILITY_ACTION_MISMATCH`; if requester and reviewer identities are equal the system shall return `E_CAPABILITY_SEPARATION_OF_DUTIES`.
- When the configured capability lifetime of 30 through 900 seconds has ended, the system shall return `E_CAPABILITY_EXPIRED` before writing a reservation, decision, receipt, or audit event.
- If request audience differs by at least 1 character, the system shall return `E_CAPABILITY_WRONG_AUDIENCE` before any write.
- If request resource differs by at least 1 character, the system shall return `E_CAPABILITY_WRONG_RESOURCE` before any write.
- If subject, scope, environment, or action digest differs, the system shall return its exact `E_CAPABILITY_*` reason before any write.
- If requested or live committed cost exceeds either the grant ceiling or AgentSpec hard budget by at least 1 cent, the system shall return `E_CAPABILITY_OVER_BUDGET` before any write.
- When every bound field matches, the system shall return `TOOL_CALL_AUTHORIZED`, `CAPABILITY_SCOPE_ENFORCED`, and `CAPABILITY_BUDGET_BOUND` after atomically consuming exactly 1 grant, reserving exactly 1 cost entry, and appending exactly 1 allow decision, receipt, and audit event.
- If a consumed grant is submitted again, the system shall return `E_CAPABILITY_REPLAYED` with exactly 0 additional writes.
- When an operator revokes an active grant, the system shall return `CAPABILITY_REVOKED` and `CAPABILITY_REVOCATION_ENFORCED`; the next authorization attempt shall return `E_CAPABILITY_REVOKED`.
- When status is requested, the system shall return `TRUST_DECISION_EXPLAINED` with policy `trust-policy.v1`, grants, and allow decisions.
- When Trust evidence is appended, the system shall return `TRUST_EVIDENCE_REDACTED` and omit raw credentials, tokens, secrets, and tool payloads.
- When rendered at 390 and 1440 CSS pixels, the system shall return `TRUST_UI_RESPONSIVE` after showing issuance, authorization, revocation, state, expiry, and cost controls without horizontal overflow.
- The system shall return `CONVEX_ONLY_STACK` after detecting no second application backend.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Authorize one exact approved action
  Given an independently approved run and one active five-minute capability
  When subject audience scope resource environment digest and cost match
  Then TOOL_CALL_AUTHORIZED consumes exactly one grant reserves exactly one cost and appends one allow decision

Scenario: Refuse substituted or stale authority
  Given one active capability
  When its audience or resource differs by one character or its expiry is at the current millisecond
  Then E_CAPABILITY_WRONG_AUDIENCE or E_CAPABILITY_WRONG_RESOURCE or E_CAPABILITY_EXPIRED leaves reservation decision receipt and audit counts unchanged

Scenario: Stop replay and emergency-revoked access
  Given one consumed grant and one operator-revoked grant
  When each grant is submitted for authorization
  Then E_CAPABILITY_REPLAYED and E_CAPABILITY_REVOKED permit zero new writes
```

## SHOULD - Technical/structural

- ADR: `adr/agent-cloud-trust-capabilities-v1.md`.
- Convex API: `products/agent-cloud/app/convex/trust.ts`.
- UI: `products/agent-cloud/app/src/components/TrustGatewayPanel.tsx`.

### Authorized bounded constants

- Policy is `trust-policy.v1`; TTL is 30 through 900 seconds and UI default is 300 seconds.
- Cost values are integer cents from 1 through 1000000; UI defaults are 20-cent grant and 15-cent request.
- Subject and audience are 1 through 120 characters, scope 1 through 160, resource 1 through 300, and revocation reason 1 through 500.
- Environments are `test` and `production`; risks are `low`, `moderate`, and `high`.
- Browser widths are 390 and 1440 CSS pixels.
- Icons are 14, 15, 16, 17, 22, and 24 CSS pixels; cents-to-dollar display uses a divisor of 100 and 2 decimal places.
- Existing interface typography weights are 400, 500, 600, 700, and 800.

## SHOULD NOT - Implementation details

- No signed-token claim, connector invocation, raw provider credential, production branch write, autonomous approval, or deny-decision persistence in this alpha.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `CAPABILITY_ISSUED` is absent | write 0 grants |
| 2 | `CAPABILITY_SHORT_LIVED` is absent | write 0 grants |
| 3 | `CAPABILITY_APPROVAL_BOUND` is absent | write 0 grants |
| 4 | `E_CAPABILITY_APPROVAL_REQUIRED` exists | write 0 grants |
| 5 | `E_CAPABILITY_ACTION_MISMATCH` exists | write 0 grants |
| 6 | `E_CAPABILITY_SEPARATION_OF_DUTIES` exists | write 0 grants |
| 7 | `E_CAPABILITY_EXPIRED` exists | write 0 authorization records |
| 8 | `E_CAPABILITY_WRONG_AUDIENCE` exists | write 0 authorization records |
| 9 | `E_CAPABILITY_WRONG_RESOURCE` exists | write 0 authorization records |
| 10 | any other `E_CAPABILITY_*` mismatch exists | write 0 authorization records |
| 11 | `E_CAPABILITY_OVER_BUDGET` exists | write 0 authorization records |
| 12 | `TOOL_CALL_AUTHORIZED` exists | consume 1 grant and reserve 1 cost atomically |
| 13 | `E_CAPABILITY_REPLAYED` exists | write 0 additional records |
| 14 | `CAPABILITY_REVOKED` is absent | keep grant active |
| 15 | `CAPABILITY_REVOCATION_ENFORCED` is absent | block revocation success |
| 16 | `E_CAPABILITY_REVOKED` exists | write 0 authorization records |
| 17 | `TRUST_DECISION_EXPLAINED` is absent | block status success |
| 18 | `TRUST_EVIDENCE_REDACTED` is absent | block release |
| 19 | `TRUST_UI_RESPONSIVE` is absent | block UI release |
| 20 | `CONVEX_ONLY_STACK` is absent | block release |
