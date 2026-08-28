# ADR: Outcome Agent Exchange v1

## Status

Accepted for the local deployable application. External payment rails and protocol endpoints remain disabled until deployment-specific credentials, URLs, authorization audiences, and provider read-backs are verified.

## Decision

Agent Oven exposes a server-owned catalog of fixed-price outcome agents. A hire creates an immutable outcome contract that binds the caller, intent digest, delegation depth, price, authority boundary, evidence checklist, and expiry. Work may settle only after every required evidence item passes deterministic validation and a different authenticated identity records the verifier verdict.

The initial settlement rail is the existing internal platform-credit ledger. Stripe Connect, Machine Payments Protocol, and x402 are advertised only as setup-required integration paths. A2A and remote MCP endpoints are likewise setup-required until a real deployment proves HTTPS routing and OIDC resource-audience enforcement.

## Consequences

- Agent-to-agent hiring uses the same authenticated Convex functions and policy checks as the human UI.
- Delegation is limited to one hop in v1.
- Workers cannot verify their own result or release payment.
- Price and evidence requirements are server-owned; clients cannot weaken them.
- Failed, missing, unknown, duplicated, or malformed evidence blocks settlement.
- Cancellation or dispute releases reserved credits exactly once.
- No claim of escrow, external-money custody, or live protocol interoperability is made without provider evidence.

## Rationale

The emerging agent economy already has mechanisms for discovery, tool access, delegated authorization, and machine payment. The missing control boundary is a portable, auditable statement of what result was purchased and what independent evidence must exist before value is released. The exchange keeps that boundary deterministic and provider-neutral.
