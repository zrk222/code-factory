# Spec: semantic-authority-plane-v1

Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core

### Description

Add a deterministic authority boundary above the sealed Oracle Contract. A probabilistic agent may declare a typed handoff, but a separate local runner may consider it only when the exact goal, approved context, sourced facts, explicit unknowns, uncertainties, limits, receiver, scope, action, expiry, and replay state all remain valid. This feature does not claim to validate private reasoning, external identity, provider execution, or semantic truth.

### Requirements (EARS)

- When `SEMANTIC_HANDOFF_REQUESTED` is supplied, the system shall return `SEMANTIC_HANDOFF_SEALED` only after binding exactly one current Oracle Contract, a versioned `urn:factory:*:vN` context, and a source with human-confirmed or trusted-source provenance. [R1]
- When `SEMANTIC_EPISTEMIC_DECLARATION_SUBMITTED` contains an empty required epistemic list or more than 16 entries in a required epistemic list, the system shall return `SEMANTIC_EPISTEMIC_INVALID` and write 0 handoff receipts; the required lists are `known`, `unknown`, `uncertain`, and `capability_limits`. [R2]
- If `SEMANTIC_SCOPE_OR_CONTEXT_INVALID` is observed because scope exceeds the Oracle Contract, context source is unapproved, or an action is consequential, the system shall return `E_SEMANTIC_AUTHORIZATION` and write 0 handoff receipts. [R3]
- When `SEMANTIC_LEASE_REQUESTED` is supplied, the system shall return `AUTHORITY_LEASE_SEALED` only for the exact handoff receiver, a subset of its scope/actions, human-confirmed or trusted-source approval, and an expiry greater than the current UTC time and no greater than 24 hours after it. [R4]
- When `SEMANTIC_ACTION_CHECK_REQUESTED` is supplied, the system shall return `E_SEMANTIC_AUTHORIZATION` with `allowed=false` for an expired lease, receiver mismatch, context mismatch, ungranted action, or scope escape. [R5]
- When `SEMANTIC_ACTION_RECORD_REQUESTED` is permitted, the system shall return `SEMANTIC_ACTION_DECISION_RECORDED` and reject a repeated `(lease_sha256, action_id)` with `E_SEMANTIC_REPLAY`. [R6]
- When `AGENT_BRIDGE_SEMANTIC_BINDING_SUBMITTED` contains a lease/action/context/actor/scope mismatch, the system shall return `E_AGENT_BRIDGE_SEMANTIC_AUTHORITY` and write 0 imported evidence receipts. [R7]
- When `SEMANTIC_STATUS_REQUESTED` reaches Graph Ops, MCP, or WebMCP, the system shall return `SEMANTIC_AUTHORITY_READ_ONLY` local receipt facts and grant zero execution, approval, publication, deployment, signing, messaging, credential, or connector authority. [R8]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: A worker receives only a bounded task
  Given a current sealed Oracle Contract
  When a planner seals a handoff and a human issues a matching 24-hour-or-less lease
  Then the receiver can obtain a local admission decision only for the exact context, action, and scoped paths
  And the decision grants no execution or approval capability

Scenario: A stale or widened task fails closed
  Given a current lease
  When an actor changes receiver, scope, action, context, or reuses an action ID
  Then the system returns a deterministic refusal before a new decision receipt is written

Scenario: An invalid context and replay are retained as exact failures
  Given `SEMANTIC_SCOPE_OR_CONTEXT_INVALID`
  When a handoff requests an unapproved context source
  Then `E_SEMANTIC_AUTHORIZATION` is returned and 0 handoff receipts are written
  And a repeated `SEMANTIC_ACTION_RECORD_REQUESTED` returns `E_SEMANTIC_REPLAY` and writes 0 receipts

Scenario: Provider evidence carries the exact handoff boundary
  Given an Agent Proof Bridge envelope with a semantic authority binding
  When its active lease does not match the actor, scope, context, or action
  Then the bridge rejects the envelope before importing its receipt

Scenario: Every UI and agent surface remains observational
  Given `SEMANTIC_STATUS_REQUESTED`
  When Graph Ops, MCP, or WebMCP loads the semantic plane
  Then `SEMANTIC_AUTHORITY_READ_ONLY` returns 0 authority
```

## SHOULD — Technical/structural

- Store immutable records only under `.factory/semantic-authority/`.
- Use canonical JSON SHA-256 hashes and deterministic ordering.
- Preserve explicit epistemic declarations as declarations, not truth claims.
- Use the independent Oracle challenge/sandbox lane for implementation behavior; do not substitute envelope validation for execution proof.

## SHOULD NOT — Implementation details

- Do not send or receive network traffic, invoke a provider, use a credential, execute a tool, mutate a candidate, issue external tokens, or claim eBPF/sidecar enforcement.
- Do not expose prompts, source bodies, URLs, secrets, model reasoning, or provider tokens.
- Do not claim that static validation proves semantic truth, theory of mind, sandbox isolation, external identity, or approval.

## Decision logic (factory candidates)

| # | if | then |
|---|---|---|
| 1 | `SEMANTIC_HANDOFF_REQUESTED` has an invalid Oracle/source binding | return `E_SEMANTIC_AUTHORIZATION` and write 0 receipts |
| 2 | `SEMANTIC_EPISTEMIC_DECLARATION_SUBMITTED` lacks one required category | return `SEMANTIC_EPISTEMIC_INVALID` and write 0 receipts |
| 3 | `SEMANTIC_LEASE_REQUESTED` widens receiver, action, or scope | return `E_SEMANTIC_AUTHORIZATION` and write 0 receipts |
| 4 | `SEMANTIC_ACTION_CHECK_REQUESTED` has expired lease or mismatched action | return `E_SEMANTIC_AUTHORIZATION` with `allowed=false` |
| 5 | `SEMANTIC_ACTION_RECORD_REQUESTED` repeats `(lease_sha256, action_id)` | return `E_SEMANTIC_REPLAY` and write 0 receipts |
| 6 | `AGENT_BRIDGE_SEMANTIC_BINDING_SUBMITTED` mismatches the lease | return `E_AGENT_BRIDGE_SEMANTIC_AUTHORITY` and write 0 receipts |
| 7 | `SEMANTIC_STATUS_REQUESTED` reaches Graph Ops or MCP | return read-only facts and grant 0 authority |
