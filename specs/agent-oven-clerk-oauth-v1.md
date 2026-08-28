# Spec: agent-oven-clerk-oauth-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Replace the Auth0 browser and Convex identity boundary with Clerk while preserving fail-closed workspace authorization. Clerk shall authenticate users through tenant-configured OAuth or enterprise SSO connections. Convex shall remain the sole server authorization boundary for Agent Oven workspaces.

### Requirements (EARS)

- The system shall accept exactly `VITE_CONVEX_URL` and `VITE_CLERK_PUBLISHABLE_KEY` as public browser identity configuration.
- The system shall mount the hosted application only when the Convex URL is HTTPS on `convex.cloud` and the Clerk key matches `pk_test_*` or `pk_live_*` with at least sixteen payload characters.
- The system shall render `ConvexProviderWithClerk` inside `ClerkProvider`, and the Convex provider shall receive Clerk `useAuth`.
- When a signed-out user selects the single primary sign-in action, the system shall open Clerk's OAuth-aware flow and use `/app` as the fallback destination.
- The system shall return a Convex auth configuration that trusts `CLERK_FRONTEND_API_URL` with application ID `convex`.
- The system shall keep OAuth and enterprise SSO providers in Clerk tenant configuration, and no provider secret shall enter source, Convex records, or `VITE_*` values.
- The system shall derive every backend identity from verified Convex context and shall re-check workspace membership.
- The system shall return Boolean facts `browserConfigurationInvalid`, `sessionInvalid`, and `serverIdentityInvalid` from exact validation inputs.
- If the Clerk publishable key or Frontend API URL is absent or malformed, the system shall fail production readiness closed.
- The system shall reject documentation claims equating repository integration with a live Clerk tenant or OAuth provider.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Reject incomplete hosted identity configuration
  Given a hosted Convex URL without a valid Clerk publishable key
  When Agent Oven evaluates the browser configuration
  Then the protected application does not mount and no configuration value is disclosed

Scenario: Mount providers in the verified order
  Given a hosted Convex URL and a valid Clerk publishable key
  When Agent Oven mounts the protected application
  Then Clerk wraps the Convex Clerk provider and the operational boundary is its child

Scenario: Offer OAuth-aware sign in
  Given a user without a verified session
  When the identity boundary renders
  Then exactly one secure sign-in action opens Clerk in automatic OAuth mode and returns to /app

Scenario: Block malformed server identity configuration
  Given a Clerk issuer URL containing a path
  When production readiness is evaluated
  Then identity readiness is invalid and control-plane activation remains blocked
```

## SHOULD - Technical/structural

- Browser provider wiring: `products/agent-cloud/app/src/HostedAppBoundary.tsx`.
- Sign-in UX: `products/agent-cloud/app/src/AuthBoundary.tsx`.
- Server identity configuration: `products/agent-cloud/app/convex/auth.config.ts`.
- Deployment validation: `products/agent-cloud/app/scripts/verify-production-env.mjs`.

## SHOULD NOT - Implementation details

- No third-party OAuth client secret is committed or placed in a browser variable.
- No Clerk organization claim replaces workspace membership authorization.
- No repository test is presented as proof of external OAuth, MFA, directory sync, or production activation.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `browserConfigurationInvalid = true` | render customer-safe provisioning state |
| 2 | `browserConfigurationInvalid = false` | mount Clerk then Convex Clerk provider |
| 3 | `sessionInvalid = true` | do not mount operational application |
| 4 | `serverIdentityInvalid = true` | mark identity readiness invalid |
