# Enterprise security architecture

## Trust boundaries

- Auth0 proves the session; Convex resolves organization and workspace membership on every public operation.
- Directory roles are mapped through a server-owned allowlist. SCIM/OIDC/SAML metadata stores an opaque secret reference, never a bearer value.
- Agent knowledge is untrusted context. Only policy can authorize tools, resources, environment, spend, and human approval.
- Customer BYOK references resolve inside the hosted worker boundary. The browser and Convex records never receive raw model keys.
- Hosted work requires an active blueprint, ready inference binding, credit reservation, admission, runtime lease, heartbeat, bounded retry, settlement, and receipt.

## Abuse and isolation controls

Per-workspace rate and concurrency policies are atomically enforced before execution credits are reserved. Cross-workspace and cross-organization identifiers are rejected. Idempotency precedes admission so safe client retries neither duplicate work nor consume extra quota.

## Evidence and limitations

Current receipts are explicitly unsigned. Production activation must replace them with the repository's DSSE signing adapter, validate key rotation/revocation, and retain verification evidence. External penetration testing, Auth0 tenant review, worker-container isolation testing, and provider webhook verification are required before enterprise GA.
