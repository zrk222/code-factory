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
- When an authenticated queue retry with at most 1048576 bytes repeats the same tenant, installation, delivery id and payload hash, the system shall return `HOSTED_INGRESS_DUPLICATE_ACCEPTED` with the retained approval and evidence identifiers without creating another approval or changing its decision. [REQ-HOSTED-QUEUE-IDEMPOTENCY]
- When a delivery id is reused under the same valid installation-to-tenant mapping with a changed authenticated payload or repository/head binding, the system shall reject it with `E_WEBHOOK_REPLAY`; invalid installation-to-tenant mappings shall fail earlier with `E_INSTALLATION_TENANT`, and default non-queue ingress shall retain its existing replay rejection. [REQ-HOSTED-QUEUE-CONFLICT]
- When Cloudflare accepts a webhook, the system shall return `CLOUDFLARE_DELIVERY_QUEUED` only after validating the exact raw-body HMAC and repository allowlist, requiring `repository.full_name` to equal `repository.owner.login/repository.name`, storing a bounded private content-addressed transport body, and committing its pointer to a Queue. [REQ-HOSTED-EDGE-ACCEPT]
- When a queued delivery is consumed, the system shall return `CLOUDFLARE_DELIVERY_FORWARDED` only after rechecking its body digest and HMAC, posting the exact bytes to the configured HTTPS hosted origin with redirects disabled, validating a successful Python ingress response with matching repository, delivery id and payload digest, and acknowledging the message. [REQ-HOSTED-EDGE-FORWARD]
- When required origin, webhook secret or delivery bindings are unavailable, the system shall return `CLOUDFLARE_NOT_READY` and 503 without forwarding or accepting a delivery. [REQ-HOSTED-EDGE-CONFIG]
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
- When PostgreSQL returns an audit timestamp in a non-UTC session timezone, the system shall verify the unchanged event hash using its UTC timestamp representation and preserve all stored audit rows and hash links. [REQ-HOSTED-AUDIT-TIMEZONE]

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
- Cloudflare is transport only: it shall not implement another verifier, approval system, GitHub signer, receipt store, or durable deduplication authority. Existing PostgreSQL tenant transactions and outbox remain authoritative. A SQLite-backed Durable Object per repository contains webhook transport escrow only, keyed by delivery id and content SHA-256. Each distinct delivery retains its body for 3 days from first admission; repeating that same delivery never extends its expiry. Identical bytes in a different delivery receive a separate retention window. This covers the Workers Free source Queue and dead-letter Queue retention of 24 hours each plus 24 hours of recovery margin; alarms purge expired transport bytes. Native lifecycle tests shall verify this retention contract before live acceptance. Queue exhaustion uses a configured dead-letter queue, not silent deletion. No full service readiness follows from edge liveness. Node tests replace the Workers import and use modeled bindings/storage; they are not native storage or deployment proof.
- Deployment uses free-tier resource profiles only, never a paid activation, automatic plan upgrade or promised unlimited capacity. Queue admission failures remain explicit and cannot become successful audit evidence. Vercel is an optional lightweight backend surface, not an audit worker or persistent process; deployment requires verified plan eligibility, configured persistent storage, secrets and live readiness. The unrelated Meta connector and its Vercel routes must remain unchanged.
- Queue messages contain object keys, SHA-256 bindings and only the signature/event/delivery headers, not raw PR bodies, bearer tokens or secrets. Streaming ingress and object reads retain the existing 1048576-byte webhook bound. Callback forwarding is limited to the existing authenticated Python callback contract; no new OAuth flow or arbitrary proxy is introduced.
- Data model: PostgreSQL migration in `factoryline/hosted_storage.py`.
- Audit timestamps in `factoryline/hosted_control.py` are hashed using timezone-aware UTC `isoformat()` on writes and reads, independent of the database session timezone. For legacy compatibility, a fetched timestamp's original session representation may be used only if the full event hash matches that exact representation; arbitrary mismatches remain invalid. Never rewrite old hashes or timestamps to clear verification failures. A historical custom-clock offset that cannot be reconstructed from `TIMESTAMPTZ` remains unverifiable, not repaired by inference.
- API: dependency-injected WSGI application in `factoryline/hosted_api.py`.
- Network: bounded transport interfaces in `factoryline/hosted_identity.py` and the GitHub publisher in `factoryline/hosted_api.py`.
- Deployment: optional `hosted` dependencies and container reference files.

### Edge transport contract
- `deploy/cloudflare/evidence-app.mjs` exports Worker handlers `fetchRequest(request, env)` and `consumeMessage(message, env)`, plus the SQLite-backed `DeliveryEscrow` class. Configure `HOSTED_ASSURANCE_ORIGIN` as an HTTPS origin without credentials, path, query or fragment; `ALLOWED_REPOSITORIES` as a nonempty JSON array of `owner/name` strings; and `GITHUB_WEBHOOK_SECRET` with at least 32 UTF-8 bytes. Bind `DELIVERY_BODIES` to the Durable Object namespace and `DELIVERIES` to the producer Queue. Missing configuration returns 503, not successful admission.
- HTTP routes are `GET /healthz` (liveness), `GET /readyz` (requires configured bindings and a successful backend readiness response), and `POST /v1/github/webhooks`. Other routes return 404. Valid signed pings return 200 without escrow; other authenticated non-PR events return 202 as ignored, not forwarded.
- The Queue pointer has only `repository`, `digest`, `delivery`, `event`, and `signature`. `event` must be `pull_request`; `delivery` is a UUID; `digest` is lowercase SHA-256. The consumer retrieves `DeliveryEscrow.get(delivery, digest)` from the repository's deterministic object and repeats digest, HMAC and repository checks. `put(delivery, digest, bytes, expiresAt)` validates bounded bytes and caps expiry at the three-day retention window. The composite SQLite key is `(delivery_id, digest)`; duplicate inserts do not extend expiry.
- `DeliveryEscrow` uses the inherited `DurableObject` context after `super(ctx, env)`; it does not replace `this.ctx` or introduce a custom context capture. Node-only tests model that base-context property explicitly without claiming a native runtime.
- Forwarding is restricted to the configured origin's `/v1/github/webhooks`, with a 5-second timeout, redirects disabled, and only content type plus signature/event/delivery and `X-Factory-Delivery-Mode: queue-retry` headers. A 200, 201 or 202 JSON response must contain a transactional or accepted-duplicate ingress marker and matching repository, delivery id and payload digest before acknowledgement. Failure calls `message.retry()` without returning a successful receipt. The deployment must attach a dead-letter Queue and bounded consumer retries before live acceptance.

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
| 6 | `HOSTED_INGRESS_DUPLICATE_ACCEPTED` | retain exactly one prior delivery and approval |
| 7 | `E_WEBHOOK_REPLAY` | reject conflicting delivery reuse |
| 8 | `CLOUDFLARE_DELIVERY_QUEUED` | acknowledge durable transport acceptance only |
| 9 | `CLOUDFLARE_DELIVERY_FORWARDED` | acknowledge verified hosted ingress only |
| 10 | `CLOUDFLARE_NOT_READY` | reject with 503 before side effects |
