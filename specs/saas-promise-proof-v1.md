# Spec: saas-promise-proof-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core

### Description

Compare a human-reviewed SaaS promise and provider-neutral OAuth/OIDC contract
with supplied, build-bound lifecycle facts. The verifier is local, read-only,
fail-closed, and has no provider, billing, deployment, or approval authority.

### User roles

- Builder: supplies a bounded contract and secret-free observed evidence.
- Reviewer: inspects the receipt and retains deployment and release authority.
- Operator: may use read-only CLI, Graph Ops, MCP, WebMCP, or JetBrains views.

### Requirements (EARS)

- The system shall accept OIDC or OAuth2 contracts using authorization code with PKCE or client credentials.
- If an authorization-code contract does not require PKCE, the system shall return `SAAS_PROOF_PKCE_REQUIRED` before receipt creation.
- If an input contains a raw token, secret, cookie, authorization value, or code verifier, the system shall return `SAAS_PROOF_SECRET_REJECTED` before receipt creation.
- If the provider issuer is not an absolute HTTPS URL without a fragment, the system shall return `SAAS_PROOF_ISSUER_INVALID` before receipt creation.
- The system shall emit every receipt with hashes of the exact contract bytes and evidence bytes plus the application identifier and non-empty build identifier.
- When authentication, authorization, checkout, webhook, entitlement, and feature-access observations are verified in sequence for the same subject, tenant, and entitlement, the system shall emit `SAAS_PROMISE_PERMISSION_VERIFIED`.
- If a feature-access journey crosses a subject or tenant boundary, the system shall return `SAAS_PROOF_CROSS_IDENTITY_OR_TENANT_JOURNEY` and block the verdict.
- If a required identity, tenant, entitlement, or authorization role binding is missing, the system shall block the verdict with the corresponding deterministic finding.
- If a checkout, grant, or feature-access event drifts from the reviewed SKU and entitlement promise, the system shall return `SAAS_PROOF_PROMISE_DRIFT` and block the verdict.
- If cancellation, refund, or expiry is not followed by revocation, the system shall return `SAAS_PROOF_STALE_ENTITLEMENT` and block the verdict.
- If any required observation is absent, the system shall return the named gate with status unknown and emit `SAAS_PROMISE_PERMISSION_BLOCKED`.
- The system shall emit a canonical SHA-256-bound local receipt with every authority flag false.
- When Graph Ops, MCP, WebMCP, or JetBrains reads SaaS Reality, the system shall expose receipt status without contacting or mutating an identity or billing provider.
- The system shall return `SAAS_PROOF_PUBLIC_PRIVATE_SEPARATED` after a public-artifact scan finds exactly 0 provider-specific private implementation files, configuration values, credentials, session identifiers, and customer records.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Verify one bound SaaS journey
  Given a reviewed OIDC contract and a non-empty build identifier
  When verified observations bind authentication through feature access to one subject tenant role SKU and entitlement
  Then SAAS_PROMISE_PERMISSION_VERIFIED is emitted with a canonical receipt hash
  And every authority flag is false

Scenario: Reject a cross-tenant journey
  Given checkout and entitlement observations for one tenant
  When feature access is observed for another tenant
  Then SAAS_PROOF_CROSS_IDENTITY_OR_TENANT_JOURNEY blocks the verdict

Scenario: Reject unsafe authentication material
  Given an input containing a raw access token
  When SaaS Reality validates the input
  Then SAAS_PROOF_SECRET_REJECTED is returned before receipt creation

Scenario: Preserve an unknown observation
  Given a lifecycle without a verified webhook observation
  When SaaS Reality evaluates the evidence
  Then the webhook gate remains unknown
  And SAAS_PROMISE_PERMISSION_BLOCKED is emitted

Scenario: Detect stale access
  Given a verified entitlement followed by a refund
  When no later revocation observation exists
  Then SAAS_PROOF_STALE_ENTITLEMENT blocks the verdict

Scenario: Preserve provider boundaries
  Given a valid local receipt
  When CLI Graph Ops MCP WebMCP or JetBrains renders SaaS Reality
  Then no provider network call or provider write occurs
  And no production certification deployment or approval claim is made
```

## SHOULD — Technical/structural

- Findings should be stably sorted by code and event identifier.
- Inputs should remain bounded to workspace-local regular JSON files no larger than 1 MiB.
- Public copy should explain the login-to-access chain without provider-specific setup claims.

## MAY — Deferred

- A future provider adapter may export the secret-free evidence schema from an authenticated customer-owned environment.
- A future Proof Leak Map may rank broken handoffs using existing receipts without gaining execution authority.

## Non-goals

Provider login, credential custody, network discovery, payment settlement,
entitlement mutation, deployment, certification, legal advice, or Marketplace
approval.
