# Enterprise PR assurance v1

Enterprise PR assurance v1 closes the first authenticated full-stack operation:
a GitHub pull-request event enters through a verified HMAC boundary, becomes
immutable tenant evidence, requires a separately authenticated OIDC approver,
and produces a deterministic GitHub Check request bound to the pull request's
head SHA.

## Trust flow

1. `verify_github_webhook` verifies `X-Hub-Signature-256` over the raw body
   before JSON parsing. It accepts only `pull_request` events with `opened`,
   `reopened`, or `synchronize` actions.
2. `PRAssuranceStore.register_installation` bootstraps an immutable GitHub
   installation-to-tenant mapping. Ingress rejects an absent or substituted
   mapping before reserving the delivery. The store then atomically reserves the tenant and GitHub delivery id.
   Reuse returns `E_WEBHOOK_REPLAY` and cannot create a second approval.
3. `ingest_pull_request` stores canonical evidence in the existing
   `EvidenceStore`, then creates one pending approval requested by the GitHub
   App installation identity.
4. `verify_oidc_token` verifies an RS256 compact JWT using an explicitly
   supplied offline JWKS. Issuer, audience, expiry, not-before, subject, tenant,
   groups, key id, and non-empty JTI are fail-closed checks.
5. `decide_pull_request` maps verified directory groups to control-plane roles.
   Existing policy rejects cross-tenant access, self-approval, and decision
   replay. The OIDC JTI is also single-use.
6. The result contains a canonical GitHub Checks API request. An independently
   authorized connector may publish that request; this module never does.

## Error contract

- Webhook failures use `E_WEBHOOK_*`, including signature, replay, event,
  action, delivery, body, and payload errors.
- OIDC failures use `E_OIDC_*`, including algorithm, key, signature, issuer,
  audience, expiry, not-before, claim, malformed token, and replay errors.
- Tenant, role, and approval failures retain the control-plane codes
  `E_TENANT_BOUNDARY`, `E_ACTION_DENIED`, `E_SELF_APPROVAL`, and
  `E_ALREADY_DECIDED`.

Callers should treat every error as terminal for that attempt and must not
convert a domain refusal into a successful Check.

## Operational boundary

This is a local, durable foundation—not a hosted control plane. It does not:

- discover IdP keys over the network or implement SSO enrollment or SCIM;
- install a GitHub App, exchange installation tokens, or call GitHub;
- provide PostgreSQL, row-level security, HA, backup, or disaster recovery;
- publish, merge, deploy, sign, obtain credentials, or send external messages;
- claim SOC 2, procurement readiness, or production availability.

A hosted adapter must add managed key discovery and rotation, PostgreSQL/RLS,
an authenticated API gateway, an authorized GitHub App connector, observability,
and production operations without weakening these local refusal semantics.
