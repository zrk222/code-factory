# Semantic Authority Plane

Code Factory now separates **what an agent says** from **what a separate runner may consider**. A semantic handoff is a local, hash-sealed envelope—not a capability token, provider credential, or execution command.

## The deterministic chain

`original intent → Oracle Contract → typed context + epistemic declaration → scoped handoff → expiring lease → replay-safe admission receipt → independent evidence → human decision`

The handoff must declare:

- one sealed Oracle Contract and one source-backed, versioned context URN;
- a shared goal, sender/receiver identities, scope, and narrow allowed actions;
- sourced facts, explicit unknowns, uncertainties, capability limits, and bounded sensitivity signals.

Only Oracle rules with `human_confirmed` or `trusted_source` provenance may anchor the context. Agent-proposed material remains advisory and cannot become a release rule through this path.

## What it validates

Static checks reject a handoff or admission request that has an invalid receipt, stale Oracle binding, unapproved context source, receiver mismatch, scope escape, ungranted action, expired lease, forbidden consequential action, or replayed action ID.

`factory semantic-authority handoff --root . --input handoff.json --out .factory/semantic-authority/handoffs/<id>.json --json`

`factory semantic-authority lease --root . --input lease.json --out .factory/semantic-authority/leases/<id>.json --json`

`factory semantic-authority check --root . --lease .factory/semantic-authority/leases/<id>.json --request action.json --json`

`factory semantic-authority record --root . --lease .factory/semantic-authority/leases/<id>.json --request action.json --out .factory/semantic-authority/decisions/<id>.json --json`

The `record` command records only a local, replay-safe admission receipt. It does not perform the described action.

## Cross-plane integration

- **Oracle Firewall** supplies the immutable intent, approved sources, and scope boundary.
- **Agent Proof Bridge** can optionally bind an imported provider-neutral evidence envelope to the exact active semantic lease. This is an import-time integrity check, not proof that a provider enforced the lease during its run.
- **Graph Ops** shows handoffs, leases, decisions, explicit epistemic state counts, and review-needed expiry/invalid states.
- **MCP and WebMCP** expose status only; no tool can issue a handoff, lease, approval, or external call.
- **Atomic and sandbox evidence** remain the independent execution-based validation lane. They must prove artifact behavior separately from message structure.

## Deliberate limits

The plane does not prove an agent's private reasoning, external identity, provider-side execution, sandbox isolation, semantic truth, policy interpretation, or release readiness. It sends no network traffic and exposes no prompt, source body, URL, token, or credential. An eBPF/Envoy/Kubernetes enforcement point may consume a reviewed exported policy later, but none is implied by these local receipts.
