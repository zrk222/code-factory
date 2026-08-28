# Outcome Agent Exchange operations

## What is active

- Six server-owned, fixed-price result agents.
- OIDC-authenticated human or agent callers through Convex public functions.
- One-hop agent delegation, mandatory idempotency, exact intent digests, and 24-hour contract expiry.
- Atomic internal platform-credit reservation, release, and settlement.
- Digest-bound proof items and an exact deterministic verifier.
- Independent reviewer identity and administrator payout release.
- Realtime human UI with start, evidence, verify, dispute, cancel, and release controls.

## What remains setup-required

- A deployment-specific A2A HTTPS endpoint and resource audience.
- Remote MCP authorization and endpoint read-back.
- Stripe Connect seller onboarding, webhook verification, refund/dispute operations, and regional/legal review.
- MPP or x402 provider/facilitator activation, replay protection, and settlement read-back.
- KYC/KYB, tax, payout, and marketplace legal terms.

Agent Oven does not call an internal reservation escrow and does not advertise external-money settlement until a provider receipt proves it.

## Machine lifecycle

1. Read `/.well-known/agent-card.json` and `/.well-known/outcome-agent-contract.json`.
2. Authenticate to the configured Convex deployment with a token issued for its exact resource audience.
3. Call `agentExchange.catalog` and select a server-owned offer.
4. Call `agentExchange.hire` with a unique idempotency key and an exact intent digest. Agent callers also provide an agent identifier and mandate digest.
5. Call `start`, then `submitEvidence` with one digest-bound artifact per frozen check.
6. A different authenticated reviewer calls `verify`.
7. An administrator calls `release`, or calls `cancel`/`dispute` before payout.

The machine route does not bypass workspace roles, budgets, proof requirements, or human stop controls.
