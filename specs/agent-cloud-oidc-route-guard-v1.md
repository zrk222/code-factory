# Agent Cloud OIDC Route Guard v1

## Outcome

Activate provider-configurable Auth0 OIDC for the Agent Cloud React/Convex app and require a server-derived, active workspace membership with an explicit minimum role for every operational query and mutation.

## Security invariants

1. The browser never supplies a trusted actor, role, or tenant claim.
2. Convex derives the principal from `ctx.auth.getUserIdentity()` and resolves role from `workspaceMemberships`.
3. Anonymous, revoked, under-privileged, and cross-workspace requests fail closed before data is returned or state is changed.
4. The only pre-membership write is the authenticated first-owner bootstrap for a workspace with zero memberships.
5. Missing OIDC configuration renders setup guidance and issues no operational Convex calls.
6. Provider secrets and raw identity claims never enter receipts, audit details, or client responses.

## Role matrix

| Surface | Minimum role |
| --- | --- |
| Dashboard, run detail, budget/trust status, memory reads, exports | viewer |
| Approval decisions | reviewer |
| Launches, reservations, tool authorization, memory creation, incident/release observations | operator |
| Agent configuration, provider configuration, lifecycle changes, memory correction/deletion/retention, release promotion/rollback | admin |
| Membership administration | owner |

## Acceptance gates

- Auth0 and Convex OIDC domain/application IDs are environment-configurable.
- Authenticated users can discover only their active workspaces.
- The demo workspace bootstrap creates the first owner membership atomically or requires existing membership.
- Every public operational function calls the shared workspace authorization guard.
- Behavioral tests cover anonymous, revoked, insufficient-role, and cross-workspace denial plus authorized success.
- A source-level route manifest fails if a new public operational endpoint is added without an authorization classification.
- Frontend tests cover missing configuration, signed-out, loading, and authenticated workspace states.
- `npm run verify` and architecture verification pass.

## Explicit non-claims

- This mission does not claim a production tenant deployment without real Auth0 and Convex production configuration.
- This mission does not add SCIM, enterprise directory synchronization, or organization-managed invitations.
