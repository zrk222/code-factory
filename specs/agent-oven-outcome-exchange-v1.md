# Spec: agent-oven-outcome-exchange-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description
Add a deployable Outcome Agent Exchange to Agent Oven. Authenticated humans and authenticated agent principals can discover a server-owned catalog of bounded agents, hire one against an exact outcome contract, reserve platform credits, submit evidence, and release payment only after independent deterministic verification. The first release supports real platform-credit settlement and provider-neutral external payment references; it does not claim that Stripe, MPP, x402, or bank settlement is active.

### User roles
- Workspace viewer: can inspect offers and sanitized contract status.
- Workspace operator: can hire an offer and start or submit work within an exact mandate.
- Workspace reviewer: can verify evidence only when the reviewer identity differs from the submitting identity.
- Workspace administrator: can dispute, cancel, or release a verified result.
- External agent client: uses an authenticated Convex/A2A-compatible request with the same workspace role, budget, idempotency, and delegation-depth checks.

### Requirements (EARS)
- When `OUTCOME_AGENT_CATALOG_REQUESTED` occurs, the system shall return exactly 6 server-owned starter offers with a concrete outcome, bounded authority, evidence checklist, delivery window, and fixed platform-credit result price.
- When a catalog is requested, the system shall return marker `OUTCOME_AGENT_CATALOG_READY` without a model call or user-supplied price.
- When a hire request is accepted, the system shall bind offer version, buyer workspace, caller kind, intent reference, intent digest, mandate digest, fixed price, evidence checks, delegation depth, and expiry into one immutable contract digest.
- When `OUTCOME_IDEMPOTENCY_REPLAY` occurs for the same workspace and idempotency key, the system shall return the existing contract without a second credit reservation.
- If `OUTCOME_CREDITS_INSUFFICIENT` occurs because available credits are below the fixed result price, the system shall reject the hire with `E_OUTCOME_CREDITS_INSUFFICIENT` and create no contract.
- If `OUTCOME_AGENT_MANDATE_INVALID` occurs because an agent caller omits an authenticated agent identifier or mandate digest, the system shall reject the hire.
- If `OUTCOME_DELEGATION_DEPTH_EXCEEDED` occurs because delegation depth exceeds 1, the system shall reject the hire with `E_DELEGATION_DEPTH_EXCEEDED`.
- While a contract is active, memory, offer text, evidence text, or another agent shall not change its price, checks, authority, expiry, or contract digest.
- When work begins, the system shall transition only `accepted -> running` and record the actor.
- When evidence is submitted, the system shall require one digest-bound artifact per required check and transition only `running -> evidence-submitted`.
- If `OUTCOME_EVIDENCE_INVALID` occurs because evidence contains an unknown, missing, duplicate, malformed, or failed check, deterministic verification shall fail closed without releasing credits.
- When an independent authenticated reviewer verifies complete passing evidence, the system shall transition `evidence-submitted -> verified`, bind the verdict to the evidence digest, and expose a payable result.
- If `OUTCOME_SELF_VERIFICATION` occurs because the verifier identity matches the evidence submitter identity, the system shall reject the verdict with `E_SELF_VERIFICATION_FORBIDDEN`.
- When `OUTCOME_VERDICT_PASSED` occurs and an administrator releases the verified result, the system shall return marker `OUTCOME_PAYMENT_SETTLED`, settle the exact reserved credits once, and transition `verified -> paid`.
- When `OUTCOME_PAYMENT_REPLAY` occurs after a paid result is released again, the system shall return the existing paid contract and settle 0 additional credits.
- When `OUTCOME_CONTRACT_TERMINATED` occurs because a contract is disputed or canceled before payment, the system shall release the reserved credits exactly once and preserve the evidence trail.
- When `OUTCOME_PAYMENT_READINESS_REQUESTED` occurs, the system shall return provider-neutral readiness for `platform-credits`, `stripe-connect`, `mpp`, and `x402`; the system shall return only platform credits as active until a verified external adapter is configured.
- If `OUTCOME_EXTERNAL_RAIL_UNVERIFIED` occurs because an external payment adapter lacks provider read-back evidence, the system shall return `setup-required` and settle no external money.
- When `OUTCOME_EXCHANGE_UI_RENDERED` occurs, the Outcome Exchange UI shall render the result price, proof boundary, current settlement rail, agent-callable contract, and human stop controls without claiming real-money activation.
- When `OUTCOME_PUBLIC_SURFACE_RENDERED` occurs, the Agent Oven public surface shall render an outcome-priced-agent explanation and the statement that payment is released after evidence, without an unsupported savings or revenue claim.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Hire a bounded agent once
  Given an authenticated operator with 500 available platform credits
  When the operator hires the PR Evidence Auditor twice with one idempotency key
  Then exactly one immutable contract exists and exactly one 90-credit reservation exists

Scenario: Reject recursive uncontrolled hiring
  Given an authenticated agent with a valid mandate
  When it requests delegation depth 2
  Then E_DELEGATION_DEPTH_EXCEEDED is returned and no credits are reserved

Scenario: Pay only for a verified result
  Given an accepted contract priced at 90 credits
  When work starts, complete artifact digests are submitted, and a different reviewer verifies every required check
  Then the contract is verified and an administrator can settle exactly 90 credits once

Scenario: Reject self-grading and hollow evidence
  Given a running contract
  When the submitter attempts to verify its own evidence or omits one required check
  Then verification fails closed and the reserved credits remain unreleased

Scenario: Explain external payment boundaries
  Given no external payment adapter credentials
  When a user opens the Outcome Exchange
  Then platform credits are active and Stripe Connect, MPP, and x402 are shown as setup-required
```

## SHOULD - Technical/structural
- ADR reference: `adr/agent-oven-outcome-exchange-v1.md`.
- Research reference: `docs/AGENT_ECONOMY_RESEARCH_2026.md`.
- Data model: `outcomeContracts`, `outcomeEvidenceItems`, and `outcomeVerdicts`; credit ledger gains an optional outcome contract reference.
- API contract: `agentExchange.catalog`, `agentExchange.overview`, `agentExchange.hire`, `agentExchange.start`, `agentExchange.submitEvidence`, `agentExchange.verify`, `agentExchange.release`, and `agentExchange.cancel`.
- Machine discovery: a public A2A-shaped Agent Card and JSON schemas document the catalog and authenticated hire lifecycle.
- UI contract: `AgentExchangePanel` is a first-class Control Room view.

### Authorized bounded constants
- Starter offers: exactly 6.
- Delegation depth: 0 or 1.
- Contract lifetime: 24 hours.
- Idempotency key maximum: 120 characters.
- Intent reference maximum: 500 characters.
- Digest maximum: 120 characters.
- Evidence reference maximum: 500 characters.
- Result prices: 60-160 platform credits.
- External settlement adapters remain `setup-required` unless independently configured and read back.

## SHOULD NOT - Implementation details
- No seller-supplied price, check list, authority, or payout destination.
- No model may decide whether payment is released.
- No recursive delegation beyond one hop.
- No raw credentials, wallets, card data, secrets, or payment tokens in browser-visible storage.
- No use of the word escrow for an internal reservation.
- No production real-money, KYC, tax, refund, or chargeback claim without provider evidence.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `OUTCOME_AGENT_CATALOG_READY` is absent | block catalog success |
| 2 | `OUTCOME_IDEMPOTENCY_REPLAY` exists | return existing contract and reserve 0 new credits |
| 3 | `OUTCOME_CREDITS_INSUFFICIENT` exists | return `E_OUTCOME_CREDITS_INSUFFICIENT` |
| 4 | `OUTCOME_AGENT_MANDATE_INVALID` exists | reject hire |
| 5 | `OUTCOME_DELEGATION_DEPTH_EXCEEDED` exists | return `E_DELEGATION_DEPTH_EXCEEDED` |
| 6 | `OUTCOME_EVIDENCE_INVALID` exists | block verification |
| 7 | `OUTCOME_SELF_VERIFICATION` exists | return `E_SELF_VERIFICATION_FORBIDDEN` |
| 8 | `OUTCOME_VERDICT_PASSED` exists | transition to verified and make exact reservation payable |
| 9 | `OUTCOME_PAYMENT_REPLAY` exists | return existing paid contract and settle 0 new credits |
| 10 | `OUTCOME_CONTRACT_TERMINATED` exists | release exact reservation once |
| 11 | `OUTCOME_EXTERNAL_RAIL_UNVERIFIED` exists | display `setup-required` and do not settle external money |
