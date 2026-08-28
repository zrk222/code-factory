# Clerk OAuth boundary

Agent Oven uses Clerk for browser authentication and Convex for server authorization. Clerk may expose social OAuth and enterprise SSO choices configured by the tenant; no provider client secret is shipped in this repository or accepted by the browser configuration.

## Activation

1. Create a Clerk application.
2. In Clerk, activate the Convex integration and copy the Frontend API URL.
3. Enable only the approved social or enterprise connections. Production social connections require provider-owned OAuth credentials configured in Clerk.
4. Set `VITE_CLERK_PUBLISHABLE_KEY` on the web host.
5. Set `CLERK_FRONTEND_API_URL` in the Convex deployment.
6. Synchronize Convex auth configuration, then exercise sign-in, sign-up transfer, sign-out, account linking, revoked-session denial, and cross-workspace denial.

## Trust boundary

- `ClerkProvider` owns the browser session UX.
- `ConvexProviderWithClerk` supplies a Clerk token to Convex.
- `convex/auth.config.ts` accepts only the Clerk provider with audience `convex`.
- Convex membership checks—not OAuth claims or memory—authorize workspace operations.
- OAuth tokens for optional downstream connectors are a separate consent and secret-storage boundary.

Repository tests prove configuration rejection, provider wiring, redacted readiness reporting, and application authorization behavior. They do not prove that an external Clerk application, OAuth provider, MFA policy, or enterprise connection is active.
