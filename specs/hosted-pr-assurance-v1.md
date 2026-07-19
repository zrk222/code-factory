# Spec: hosted-pr-assurance-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core
### Description
Add a deployable hosted adapter around the authenticated PR-assurance core.
The adapter uses PostgreSQL row-level tenant isolation, HTTPS JWKS rotation,
OIDC approver authentication, a transactional GitHub Check outbox, readiness
checks, and an explicitly configured GitHub App publisher.

### User roles
- GitHub App installation: submits signed pull-request webhooks.
- Enterprise approver: submits one OIDC-authenticated approval decision.
- Hosted worker: publishes committed outbox records with GitHub App authority.
- Platform operator: provisions tenant mappings, secrets, database, and runtime.

### Requirements (EARS)
- The system shall return marker `POSTGRES_RLS_BOUND` only after migrations enable and force row-level security for delivery, token-use, and outbox tables using the transaction-local tenant setting.
- The system shall return marker `INSTALLATION_TENANT_ROUTED` only after an installation id resolves to exactly one configured tenant and webhook secret before authenticated ingress.
- When a GitHub webhook arrives, the system shall return marker `HOSTED_INGRESS_TRANSACTIONAL` only after verifying the raw HMAC body, enforcing the immutable database tenant mapping, and committing exactly one evidence, approval, and pending outbox-independent state in one PostgreSQL transaction.
- If a delivery id is reused or an installation tenant is substituted, the system shall return marker `HOSTED_INGRESS_REPLAY_REJECTED` with `E_WEBHOOK_REPLAY` or `E_INSTALLATION_TENANT` and commit zero new approvals.
- The system shall return marker `JWKS_ROTATION_PINNED` only after loading JWKS from an HTTPS URL with a network timeout of 5 seconds, a cache lifetime of 300 seconds, a redirect limit of 0 HTTP redirects, and exact issuer and audience verification by the core.
- If JWKS retrieval, shape, or freshness fails, the system shall return marker `JWKS_FAILURE_CLASSIFIED` with one stable JWKS domain error and shall not reuse a cache older than 900 seconds.
- When an approver submits a terminal decision, the system shall return marker `HOSTED_DECISION_TRANSACTIONAL` only after consuming one OIDC JTI, enforcing tenant and self-approval rules, updating approval state, and inserting exactly one GitHub Check outbox row in one PostgreSQL transaction.
- The system shall return marker `CHECK_OUTBOX_TRANSACTIONAL` only when the approval and unique outbox record commit or roll back together.
- When the hosted worker dispatches an outbox row, the system shall return marker `GITHUB_APP_PUBLICATION_BOUND` only after minting a GitHub App JWT valid for at most 600 seconds, exchanging it for the exact installation token, publishing the bound check request over HTTPS, and storing the returned check-run id.
- If GitHub publication fails, the system shall return marker `OUTBOX_FAILURE_RETAINED` after retaining the outbox row with a classified error and at most 25 attempts; the approval decision shall remain committed and visible as publication pending.
- When a remote check-run id is stored, the system shall return marker `OUTBOX_PUBLISHED`.
- The system shall return marker `HOSTED_ROUTES_BOUND` only when the WSGI application exposes `GET /healthz`, `GET /readyz`, `POST /v1/github/webhooks`, and `POST /v1/approvals/{approval_id}/decision` with JSON bodies limited to 65536 bytes.
- The system shall return marker `HOSTED_AUTH_BOUNDARY` only when the decision route requires a Bearer token and the webhook route derives tenant and secret from the configured installation rather than caller headers.
- The system shall return marker `HOSTED_EVENTS_SECRET_FREE` only when structured operation events and responses contain zero webhook secrets, OIDC tokens, GitHub private keys, or installation tokens.
- The system shall return marker `HOSTED_ADAPTER_CHALLENGED` only after hostile tests reject webhook replay, tenant substitution, stale JWKS, unsigned approval, self-approval, duplicate decision, and publisher credential leakage.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Hosted PR assurance completes through a transactional outbox
  Given PostgreSQL row-level security, one installation tenant mapping, HTTPS JWKS, and GitHub App credentials
  When a signed pull-request webhook and distinct OIDC approver decision are accepted
  Then POSTGRES_RLS_BOUND and INSTALLATION_TENANT_ROUTED are proven
  And JWKS_ROTATION_PINNED and HOSTED_AUTH_BOUNDARY are proven
  And CHECK_OUTBOX_TRANSACTIONAL commits one pending check
  And a worker publishes the exact head SHA and stores the GitHub check-run id

Scenario: Hosted trust substitutions fail closed
  Given a valid tenant-a installation and pending approval
  When delivery, tenant, JWKS freshness, token signature, or approver identity is substituted
  Then no cross-tenant state is returned
  And HOSTED_ADAPTER_CHALLENGED records the classified refusals

Scenario: Every hosted requirement has executable evidence
  Given the hosted adapter smoke contract
  When hostile and architecture checks pass
  Then HOSTED_INGRESS_TRANSACTIONAL and HOSTED_INGRESS_REPLAY_REJECTED are proven
  And JWKS_FAILURE_CLASSIFIED and HOSTED_DECISION_TRANSACTIONAL are proven
  And GITHUB_APP_PUBLICATION_BOUND and OUTBOX_FAILURE_RETAINED are proven
  And a stored remote check id returns OUTBOX_PUBLISHED
  And HOSTED_ROUTES_BOUND and HOSTED_EVENTS_SECRET_FREE are proven

```

## SHOULD - Technical/structural
- Data model: PostgreSQL migration in `factoryline/hosted_storage.py`.
- API: dependency-injected WSGI application in `factoryline/hosted_api.py`.
- Network: bounded transport interface in `factoryline/hosted_identity.py` and `factoryline/hosted_github.py`.
- Deployment: optional `hosted` dependencies and container reference files.

### Authorized bounded constants
- Webhook routing bodies use the core 1048576-byte maximum; API decision JSON uses 65536 bytes.
- Network connect/read timeout is 5 seconds; JWKS fresh TTL is 300 seconds and hard stale limit is 900 seconds.
- GitHub App JWT is backdated by 30 seconds and expires 570 seconds after the
  current clock, preserving an at-most-600-second validity window; outbox
  attempts are at most 25.
- Outbox workers claim at most 20 rows per batch and error text is truncated to 1000 characters.
- GitHub repository owner and name segments are independently limited to 100
  characters, and JSON/text boundaries use UTF-8 encoding.
- GitHub API version is `2022-11-28`; RSA signing uses SHA-256.
- HTTP success codes are 200, 201, and 202; invalid requests use 400, 401, 403, 404, 409, or 503.
- SSAT scopes contain at most 220 lines per declared symbol and smoke checks time out after 120 seconds.
- The container reference uses Python 3.12, port 8080, 2 Gunicorn workers, 4
  threads, a 30-second health interval, a 5-second health timeout, and 3
  retries.
- Hostile-test cryptography uses RSA public exponent 65537 and 2048-bit keys.
  Fixture-only identifiers 17, 991, 4421, and epoch 1800000000 carry no
  production meaning; fixture webhook material is 32 bytes and head SHAs are
  40 hexadecimal characters.

## SHOULD NOT - Implementation details
- No caller-controlled tenant headers.
- No synchronous GitHub publication inside the approval transaction.
- No automatic database provisioning, IdP enrollment, SCIM, HA, or compliance certification claim.
- No production deployment occurs without a separately configured hosting target and credentials.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | `INSTALLATION_TENANT_ROUTED` is absent | reject webhook before authority decision |
| 2 | `JWKS_ROTATION_PINNED` is absent | reject approval before principal construction |
| 3 | `CHECK_OUTBOX_TRANSACTIONAL` is absent | roll back decision and outbox |
| 4 | `OUTBOX_FAILURE_RETAINED` | record the classified failure under the authorized outbox policy |
| 5 | `OUTBOX_PUBLISHED` | mark outbox published |
