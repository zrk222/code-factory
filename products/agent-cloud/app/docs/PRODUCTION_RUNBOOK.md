# Agent Oven production runbook

## Deployment boundary

Agent Oven is a Convex-only control plane with an Auth0 OIDC boundary. Platform credits pay for control-plane work. Customer-selected BYOK inference is billed by the model provider and can be shared at workspace level or dedicated to one agent. Activated agents depend on Agent Oven for leases, policy, credit admission, evidence, cancellation, and reconciliation.

## Required activation sequence

1. Create separate production Convex and Auth0 tenants; configure exact callback, logout, and web origins.
2. Set the browser variables and matching Convex `AUTH0_*` variables. Never place secrets in `VITE_*` values.
3. Provision billing webhook, transactional email, runtime-worker, and backup-storage credentials in an approved secret manager. Supply only opaque references.
4. Replace every `example.com` placeholder in the legal and security files. Obtain legal approval before accepting customers.
5. Restrict the CSP `connect-src` list in `vercel.json` to the exact production Convex and Auth0 hosts.
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
