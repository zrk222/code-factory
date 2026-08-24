# Agent Oven production runbook

## Deployment boundary

Agent Oven is a Convex-only control plane with a Clerk OAuth/OIDC boundary. Platform credits pay for control-plane work. Customer-selected BYOK inference is billed by the model provider and can be shared at workspace level or dedicated to one agent. Activated agents depend on Agent Oven for leases, policy, credit admission, evidence, cancellation, and reconciliation.

## Required activation sequence

1. Create separate production Convex and Clerk instances. In Clerk, activate the Convex integration, enable only approved OAuth or enterprise SSO connections, and configure custom provider credentials for production.
2. Set browser `VITE_CONVEX_URL` and `VITE_CLERK_PUBLISHABLE_KEY`. Set `CLERK_FRONTEND_API_URL` in the Convex deployment and run `npx convex dev` or the production deploy command to synchronize `auth.config.ts`. Never place the Clerk secret key or OAuth client secrets in `VITE_*` values.
3. Provision billing webhook, transactional email, runtime-worker, and backup-storage credentials in an approved secret manager. Supply only opaque references.
4. Replace every `example.com` placeholder in the legal and security files. Obtain legal approval before accepting customers.
5. Restrict the CSP `connect-src` list in `vercel.json` to the exact production Convex and Clerk hosts after the production domains are known.
6. Run `npm run verify:production-env`, `npm run verify:release`, and `npm audit --audit-level=high`.
7. Deploy the frontend, Convex functions/schema, runtime worker, backup worker, billing adapter, and email adapter from the same release identifier.
8. Run a synthetic signup, workspace bootstrap, credit reservation, template activation, BYOK binding, queued execution, cancellation, backup, and isolated restore drill.

## Go-live cockpit

Workspace administrators can read the sanitized go-live cockpit in Settings. It evaluates exactly seven server-owned controls and deliberately separates two truths:

- **Control plane live** means production identity and the public HTTPS application endpoint are configured.
- **Enterprise operations ready** additionally requires opaque references for billing, email, the isolated runtime worker, and backup storage, plus a monitored security contact.

`blocked` means a foundation control is missing or invalid. `pilot` means the hosted control plane is live while one or more enterprise operations controls still need activation. `ready` means all seven configuration contracts are valid. The cockpit never returns environment names, configured values, secret references, or identity claims to the browser. A `ready` configuration still does not prove that a reference resolves or that an external service is healthy; retain the synthetic checks and activation receipts below.

## Rollback

Pause new runtime claims, preserve queued jobs and ledger reservations, roll back frontend and functions to the previous qualified release, then reconcile or release every open reservation. Never delete audit, receipt, or transaction rows during rollback.

## External activation still required

Repository qualification cannot prove production tenant settings, DNS, provider credentials, webhook delivery, object-storage writes, outbound email, or runtime-worker capacity. Record those checks as deployment receipts.
