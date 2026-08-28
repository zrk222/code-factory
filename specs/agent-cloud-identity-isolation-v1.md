# Spec: agent-cloud-identity-isolation-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Add an authenticated, local Convex identity and workspace-isolation foundation without claiming hosted multi-tenancy. Server authorization derives the principal from `ctx.auth.getUserIdentity()` and combines issuer plus subject through Convex `tokenIdentifier`; a client-supplied workspace identifier is never sufficient authority. Existing prototype APIs remain explicitly local-only until a later OIDC wiring mission migrates every route.

### Requirements (EARS)

- If Convex returns no authenticated identity, the system shall return `E_AUTH_REQUIRED` before writing a membership, receipt, or audit event.
- When the first authenticated principal bootstraps a workspace with exactly 0 memberships, the system shall return `WORKSPACE_OWNER_BOOTSTRAPPED` after writing exactly 1 active owner membership, 1 receipt, and 1 audit event.
- If a workspace already contains at least 1 membership, the system shall return `E_BOOTSTRAP_CLOSED` before any write.
- If the derived principal has no active membership for the requested workspace, the system shall return `E_WORKSPACE_ACCESS_DENIED` before exposing workspace or AgentSpec data.
- If an authenticated member supplies an AgentSpec identifier belonging to another workspace, the system shall return `E_CROSS_TENANT_RESOURCE` before exposing that AgentSpec.
- When an owner adds one non-owner member, the system shall return `WORKSPACE_MEMBER_ADDED` after writing exactly 1 active membership, 1 receipt, and 1 audit event.
- If a non-owner attempts membership administration, the system shall return `E_ROLE_FORBIDDEN` before any write.
- When an owner revokes one non-owner active membership, the system shall return `WORKSPACE_MEMBER_REVOKED` after changing exactly 1 membership and appending non-secret receipt and audit evidence.
- If revocation or role change would remove the last active owner, the system shall return `E_LAST_OWNER_REQUIRED` before any write.
- When membership status is requested, the system shall return `WORKSPACE_ACCESS_EXPLAINED` with the authenticated subject label, role, status, and workspace identifier.
- When identity evidence is appended, the system shall return `IDENTITY_EVIDENCE_REDACTED` and omit tokens, credentials, email addresses, and raw identity claims.
- When the Settings identity readiness panel renders at 390 and 1440 CSS pixels, the system shall return `IDENTITY_UI_RESPONSIVE` after showing the authentication state, enforcement boundary, role model, and local-only limitation with exactly 0 CSS pixels of horizontal overflow.
- The system shall return `CONVEX_ONLY_STACK` after detecting no second application backend.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Bootstrap one workspace owner
  Given an authenticated principal and a workspace with exactly 0 memberships
  When the principal bootstraps ownership
  Then WORKSPACE_OWNER_BOOTSTRAPPED writes exactly 1 owner membership 1 receipt and 1 audit event

Scenario: Reject cross-workspace access
  Given an owner membership in workspace A and an AgentSpec in workspace B
  When the owner supplies workspace A and the AgentSpec identifier from workspace B
  Then E_CROSS_TENANT_RESOURCE exposes no AgentSpec fields and writes 0 records

Scenario: Keep administration owner-controlled
  Given one owner and one viewer in a workspace
  When the viewer adds or revokes a member
  Then E_ROLE_FORBIDDEN leaves membership receipt and audit counts unchanged
```

## SHOULD - Technical/structural

- Convex API: `products/agent-cloud/app/convex/access.ts`.
- UI: `products/agent-cloud/app/src/components/IdentityBoundaryPanel.tsx`.
- ADR: `adr/agent-cloud-identity-isolation-v1.md`.

### Authorized bounded constants

- Roles are `owner`, `admin`, `operator`, `reviewer`, and `viewer`; membership states are `active` and `revoked`.
- Token identifiers and member labels are 1 through 240 characters; administration rationale is 1 through 500 characters.
- UI icon sizes are 14, 16, 17, 18, 20, and 22 CSS pixels; browser widths are 390 and 1440 CSS pixels.
- Existing interface typography weights are 400, 500, 600, 700, and 800.

## SHOULD NOT - Implementation details

- No hosted multi-tenancy claim, OIDC provider selection, SSO login UX, SCIM, production tenant migration, client-supplied identity, raw token storage, billing, or production connector action.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `E_AUTH_REQUIRED` exists | write 0 records |
| 2 | `WORKSPACE_OWNER_BOOTSTRAPPED` is absent | block bootstrap success |
| 3 | `E_BOOTSTRAP_CLOSED` exists | write 0 records |
| 4 | `E_WORKSPACE_ACCESS_DENIED` exists | expose 0 workspace records |
| 5 | `E_CROSS_TENANT_RESOURCE` exists | expose 0 AgentSpec records |
| 6 | `WORKSPACE_MEMBER_ADDED` is absent | keep membership count unchanged |
| 7 | `E_ROLE_FORBIDDEN` exists | write 0 records |
| 8 | `WORKSPACE_MEMBER_REVOKED` is absent | keep membership active |
| 9 | `E_LAST_OWNER_REQUIRED` exists | keep owner membership active |
| 10 | `WORKSPACE_ACCESS_EXPLAINED` is absent | block status success |
| 11 | `IDENTITY_EVIDENCE_REDACTED` is absent | block evidence success |
| 12 | `IDENTITY_UI_RESPONSIVE` is absent | block UI release |
| 13 | `CONVEX_ONLY_STACK` is absent | block release |
