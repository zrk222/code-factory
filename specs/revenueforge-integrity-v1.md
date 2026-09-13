# Spec: revenueforge-integrity-v1

Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core

RevenueForge shall provide a local, deterministic integrity plane for billing
observations and monetization experiments. It normalizes supplied StoreKit,
Play Billing, and server events, collapses exact retries by an idempotency key,
rejects conflicting or unverified observations, validates experiment guardrails,
and emits a combined receipt. It never contacts a provider, grants an
entitlement, changes a price, starts an experiment, promotes a winner, deploys,
or reads credentials.

### Requirements (EARS)

- The system shall reject any request that lacks a manifest-matching sandbox or TestFlight build, 1–1000 billing events, a provider, transaction id, declared product, supported event type, timezone-aware timestamp, and `verified=true`, and shall emit `REVENUEFORGE_BILLING_INVALID`.
- When two of at most 1000 input events share a provider, transaction id, event type, and RFC3339 date-time, the system shall emit one observation and shall mark at most 1 duplicate event as `duplicate`; when product, entitlement, or verification fields differ, it shall emit `REVENUEFORGE_BILLING_CONFLICT`.
- When one transaction id has different products, or one provider/date-time identity has different event types, the system shall emit a blocked reconciliation finding and shall return an empty `grant_candidates` list.
- The system shall emit entitlement state only after verified purchase or renewal observations followed by deterministic refund or revocation transitions, and shall emit `inactive` for restore-only or unverified input.
- The system shall reject an experiment object unless the object contains a hypothesis, one primary metric, two or three treatments including one control, a declared cohort, a 1–90 day window, a 20–1,000,000 minimum sample, and at least one numeric guardrail.
- If an experiment includes a price mutation, winner or promotion instruction, forbidden paywall pattern, or agent-supplied release decision, the system shall emit `REVENUEFORGE_EXPERIMENT_AUTHORITY_REJECTED` or `REVENUEFORGE_DARK_PATTERN_REJECTED` and shall not write a start instruction.
- The system shall emit `AWAITING_HUMAN_APPROVAL` for an unapproved experiment and `READY_FOR_HUMAN_START` for a separately approved experiment, while setting provider writes and winner promotion to false.
- The system shall compare the current manifest hash with an optional baseline, shall emit billing and experiment findings, and shall emit `READY_FOR_HUMAN_REVIEW` or `REVIEW_REQUIRED` as the deterministic decision.
- The system shall write every output inside the workspace atomically, attach a canonical SHA-256 receipt, include an `action_summary`, and set all external authority flags to false.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: duplicate billing retries are idempotent
  Given two identical verified App Store purchase observations
  When billing reconciliation runs
  Then one observation is applied and one is marked duplicate
  And the reconciliation is not blocked

Scenario: conflicting retries fail closed
  Given two observations with the same idempotency key and different products
  When billing reconciliation runs
  Then the marker is `REVENUEFORGE_BILLING_CONFLICT`
  And no grant candidate is emitted

Scenario: refund revokes a previously verified entitlement
  Given a verified purchase followed by a verified refund
  When billing reconciliation runs
  Then the final entitlement state is inactive
  And the receipt remains read-only

Scenario: an experiment needs independent approval
  Given a two-treatment experiment with a numeric refund-rate guardrail
  When no separate approval is supplied
  Then status is `AWAITING_HUMAN_APPROVAL`
  And provider writes and winner promotion remain false

Scenario: an agent cannot set a release outcome
  Given an experiment contains a winner or promotion instruction
  When experiment planning runs
  Then the command fails with `REVENUEFORGE_EXPERIMENT_AUTHORITY_REJECTED`

Scenario: integrity receipt exposes manifest drift
  Given a valid ledger was produced for one manifest
  And the current manifest hash differs from a supplied baseline
  When the integrity evaluation runs
  Then the decision is `REVIEW_REQUIRED`
  And the next action is human manifest reassessment
```

## SHOULD — Technical/structural

- API: `reconcile_billing_events`, `plan_revenue_experiment`,
  `evaluate_revenue_integrity`, and `revenue_integrity_projection` in
  `factoryline.revenue_integrity`.
- Bounds: input ≤1 MiB, events ≤1000, treatments ≤3, experiment window ≤90
  days, sample size ≤1,000,000, and paths beneath the selected workspace.
- Receipts use `factory.revenueforge.billing-ledger.v1`,
  `factory.revenueforge.experiment-plan.v1`, and
  `factory.revenueforge.integrity.v1`.
- Billing output is compatible with the continuous-controls receipt contract by
  exposing `control_id` and a `PASS`/`BLOCKED` verdict.

## Declared facts

`build_binding_valid`, `billing_input_valid`, `idempotency_duplicate`,
`idempotency_conflict`, `transaction_product_conflict`,
`verified_transition_only`, `grant_candidates_empty_on_conflict`,
`experiment_shape_valid`, `experiment_authority_safe`, `experiment_approved`,
`manifest_current`, `ledger_receipt_valid`, `experiment_receipt_valid`,
`baseline_current`, and `mandatory_evidence_current` are the facts consumed by
the decision table.

## SHOULD NOT — Non-goals

- Do not fetch StoreKit, Play Billing, App Store Connect, or payment-provider
  data from the deterministic core.
- Do not store customer identity, signed payloads, JWS values, secrets, or
  provider tokens.
- Do not claim revenue lift, App Review approval, legal compliance, or
  production entitlement correctness from local observations alone.

## Decision logic

| # | if | then |
|---|---|---|
| 1 | `build_binding_valid` is false or `billing_input_valid` is false | reject input and emit the stable billing error |
| 2 | `idempotency_conflict` is true or `transaction_product_conflict` is true | block reconciliation and emit no grant candidate |
| 3 | `verified_transition_only` is true and `grant_candidates_empty_on_conflict` is true | emit a reconciled ledger with `PASS` verdict |
| 4 | `experiment_shape_valid` is true and `experiment_approved` is false | emit `AWAITING_HUMAN_APPROVAL` |
| 5 | `experiment_shape_valid` is true, `experiment_authority_safe` is true, and `experiment_approved` is true | emit `READY_FOR_HUMAN_START` |
| 6 | `ledger_receipt_valid` is false, `baseline_current` is false, or `mandatory_evidence_current` is false | emit `REVIEW_REQUIRED` with one remediation |
| 7 | `manifest_current` is true, `ledger_receipt_valid` is true, and `mandatory_evidence_current` is true | emit `READY_FOR_HUMAN_REVIEW` while retaining human authority |
