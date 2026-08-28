# Spec: agent-cloud-budget-enforcement-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Add supervised, atomic inference-cost reservations to the local Convex PR Assurance pilot. The ledger proves that concurrent reservation requests cannot exceed the AgentSpec hard budget, supports exact reconciliation and release, and explains refusal before a paid call. This is a gateway simulation and accounting contract, not provider invocation, provider billing, or hosted payment processing.

### Requirements (EARS)

- When one model call is admitted, the system shall return `BUDGET_RESERVED_ATOMICALLY` after counting settled run cost plus every outstanding reservation and writing exactly 1 reservation only when the total remains at or below the AgentSpec hard budget.
- If a reservation would make committed cost exceed the AgentSpec hard budget by at least 1 cent, the system shall return `E_BUDGET_EXCEEDED` before writing a reservation, usage event, receipt, or audit event.
- When two concurrent reservations compete for insufficient remaining budget, the system shall return `BUDGET_RACE_CONTAINED` after admitting exactly 1 request and rejecting exactly 1 request without exceeding the ceiling.
- When an identical call key is replayed with identical provider, model, and estimate, the system shall return `BUDGET_RESERVATION_REPLAYED` with the original reservation and exactly 0 additional writes.
- If a call key is replayed with different provider, model, or estimate, the system shall return `E_CALL_KEY_CONFLICT` before any write.
- When a reserved call is reconciled, the system shall return `BUDGET_RECONCILED` after requiring actual cost at or below the reservation, settling exactly 1 reservation, increasing run actual cost by that amount, and appending exactly 1 usage event, 1 receipt, and 1 audit event.
- If actual cost exceeds the reservation by at least 1 cent, the system shall return `E_ACTUAL_EXCEEDS_RESERVATION` while leaving the reservation unchanged.
- When an unused reservation is released, the system shall return `BUDGET_RELEASED` after releasing exactly 1 reservation and appending non-secret receipt and audit evidence.
- When budget status is requested, the system shall return `BUDGET_STATUS_EXPLAINED` with exactly 6 summary fields: hard-limit cents, settled cents, reserved cents, remaining cents, utilization percentage, and termination reason.
- When budget receipts are appended, the system shall return `BUDGET_EVIDENCE_REDACTED` after exposing no prompt, response, credential, or provider-key content.
- When the budget console renders at 390 and 1440 CSS pixels, the system shall return `BUDGET_UI_RESPONSIVE` after exposing reserve, reconcile, release, remaining-budget, and refusal controls without horizontal overflow.
- The system shall return `CONVEX_ONLY_STACK` after proving Convex is the only application backend.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Contain a concurrent budget race
  Given settled cost of 120 cents and a hard budget of 450 cents
  When two concurrent requests each reserve 200 cents
  Then BUDGET_RACE_CONTAINED admits exactly 1 request rejects exactly 1 request and committed cost remains at or below 450 cents

Scenario: Refuse spend before side effects
  Given insufficient remaining budget
  When a model call requests a reservation
  Then E_BUDGET_EXCEEDED leaves reservation usage receipt and audit counts unchanged

Scenario: Replay an identical reservation
  Given one reserved call key
  When the identical request is submitted again
  Then BUDGET_RESERVATION_REPLAYED returns the original reservation with exactly 0 new writes

Scenario: Reconcile and release reservations
  Given two outstanding reservations
  When one is reconciled within its estimate and the other is released
  Then BUDGET_RECONCILED appends exact usage evidence and BUDGET_RELEASED restores remaining budget

Scenario: Explain the hard stop
  Given one run with settled and reserved cost
  When the budget console renders at 390 and 1440 CSS pixels
  Then BUDGET_STATUS_EXPLAINED shows the exact ledger and BUDGET_UI_RESPONSIVE has no overflow
```

## SHOULD - Technical/structural

- ADR reference: `adr/agent-cloud-budget-enforcement-v1.md`.
- Convex API: `products/agent-cloud/app/convex/budget.ts`.
- UI: `products/agent-cloud/app/src/components/RunPanel.tsx`.

### Authorized bounded constants

- Monetary values use integer cents. Reservation estimate is 1 through 1000000 cents and actual cost is 0 through 1000000 cents.
- Provider, model, and call key are each 1 through 120 characters.
- The default browser rehearsal reserves 200 cents against settled cost 120 cents and hard budget 450 cents.
- Deterministic fixtures also authorize estimates of 50, 100, 127, and 331 cents; actual costs of 80 and 101 cents; remaining values of 130 and 250 cents; and utilization 71 percent.
- Browser widths are 390 and 1440 CSS pixels; icon sizes are 14, 15, 16, 17, 18, 20, 21, 22, 24, 26, 27, and 30 CSS pixels.
- Percentage display is capped at 100; UI default reservation is 0.25 dollars and default reconciliation is 0.21 dollars.
- Existing rationale and audit detail bounds remain 500 characters; test and browser commands time out after 120 seconds.
- Existing typography weights are 400, 500, 600, 700, and 800; `PROOF LINE 01` remains authorized.

## SHOULD NOT - Implementation details

- No provider invocation, token estimation claim, hosted billing, payment processing, currency conversion, monthly/team/tenant aggregation, or autonomous budget increase.
- No prompts, responses, credentials, or provider keys in budget receipts or audit events.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `BUDGET_RESERVED_ATOMICALLY` is absent | block provider-call simulation |
| 2 | `E_BUDGET_EXCEEDED` exists | add exactly 0 reservation usage receipt and audit records |
| 3 | `BUDGET_RACE_CONTAINED` is absent | block release |
| 4 | `BUDGET_RESERVATION_REPLAYED` exists | add exactly 0 records |
| 5 | `E_CALL_KEY_CONFLICT` exists | keep the original reservation unchanged |
| 6 | `BUDGET_RECONCILED` is absent | keep the reservation reserved and run cost unchanged |
| 7 | `E_ACTUAL_EXCEEDS_RESERVATION` exists | keep the reservation unchanged |
| 8 | `BUDGET_RELEASED` is absent | keep the reservation reserved |
| 9 | `BUDGET_STATUS_EXPLAINED` is absent | block the budget console |
| 10 | `BUDGET_EVIDENCE_REDACTED` is absent | block receipt success |
| 11 | `BUDGET_UI_RESPONSIVE` is absent | block UI release |
| 12 | `CONVEX_ONLY_STACK` is absent | block release |
