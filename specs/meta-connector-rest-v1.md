# Meta AI Connectors REST resource v1
Status: implementation in progress
SpecFactor-target: 0.75-2.5

Code Factory exposes an OAuth-protected, receipt-backed REST resource for a
linked Meta AI account. It returns bounded audit status, findings, coverage,
and repair suggestions. It does not run code, clone repositories, approve a
release, or certify a candidate. A submitted summary is attributed to the
authenticated account; its contents are not an independent attestation.

## MUST - Functional core

### Description

Code Factory shall expose bounded, account-linked audit summaries through an
isolated HTTPS resource. A stateless host shall use durable storage, verify
OAuth identity and scopes, and preserve account revocation across invocations.

### Requirements (EARS)

- When the connector runs on a stateless host, the connector shall reject `CONFIG_INVALID` for ephemeral storage before accepting account data.
- When a request reaches a mounted API path, the connector shall return `factory.meta.capabilities.v1` for the capabilities route and preserve the query string.
- When a user uploads an audit, the service shall lock the account row and reject `AUDIT_LIMIT` once that account holds 200 rows.
- When a user unlinks or relinks an account, the service shall lock the account row and reject `FRESH_LINK_REQUIRED` for stale authorization.
- When a public base URL is configured, the connector shall return an API contract with `servers` set to that exact HTTPS base, including its path prefix.
- If storage cannot connect or execute a query, the service shall reject `STORAGE_UNAVAILABLE` without returning connection credentials.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Reject ephemeral Vercel storage
  Given a stateless host and a local database path
  When the connector loads its configuration
  Then `CONFIG_INVALID` is returned before account data is accepted

Scenario: Preserve mounted route semantics
  Given an API request with a query string on the mounted capabilities route
  When the connector dispatches the request
  Then `factory.meta.capabilities.v1` is returned and the query string is preserved

Scenario: Read a summary after another function invocation
  Given a durable database and a valid write-scoped account token
  When the first invocation uploads a bounded audit and the second lists audits
  Then the second invocation returns the exact uploaded audit ID

Scenario: Enforce the retained audit cap
  Given an account with 200 retained audits
  When another upload checks the locked account row
  Then `AUDIT_LIMIT` is returned without inserting an audit

Scenario: Require a fresh relink grant
  Given an unlinked account and a token issued before unlinking
  When the account attempts to relink
  Then `FRESH_LINK_REQUIRED` is returned

Scenario: Publish the configured API base
  Given a public HTTPS base with a path prefix
  When the connector returns its API contract
  Then `servers` contains that exact public HTTPS base

Scenario: Hide database connection details
  Given an unavailable audit database
  When the connector queries account data
  Then `STORAGE_UNAVAILABLE` is returned without connection credentials

```

## SHOULD - Technical/structural

Vercel uses `api/index.py` and requires a dedicated PostgreSQL DSN in
`FACTORY_META_DATABASE`. The API mount is `/api`. The public base is configured
with `FACTORY_META_PUBLIC_BASE_URL`. The preferred hostname is
`cf.wizeme.app`, assigned directly to the Code Factory project.
The dedicated Clerk profile verifies token activity, client ID, and scopes
through live introspection because Clerk's OAuth tokens do not carry the
generic profile's required `tenant_id`, `groups`, and fixed audience claims.
The generic OIDC profile keeps its existing 15-minute JWT ceiling.

## Routes

`GET /health`, `GET /openapi.json`, and `GET /v1/capabilities` are public.
`GET /v1/account`, `GET /v1/audits`, `GET /v1/audits/{id}`,
`GET /v1/audits/{id}/findings`, `GET /v1/audits/{id}/coverage`, and
`GET /v1/audits/{id}/repair-plan` require `cf.audit.read`.
`POST /v1/audits`, `DELETE /v1/audits/{id}`, and `DELETE /v1/account`
require `cf.audit.write`. Account deletion removes all its audit summaries and
revokes its local link. In the generic OIDC profile,
`POST /v1/account/relink` requires `cf.audit.link` from a fresh OAuth
authorization whose `auth_time` follows the unlink time. Old access tokens
cannot relink an account. Clerk's token introspection does not provide
`auth_time`, so the Clerk profile does not advertise self-service relink and
returns `RELINK_UNSUPPORTED`; contact support to restore a deleted account.

## OAuth and hosting

Use `deploy/meta-connector/env.example` as the non-secret environment checklist
and `deploy/meta-connector/meta-onboarding.example.json` as the operator's
mapping into Meta's guided connector UI. The JSON is **not** a Meta-defined
manifest and must not be uploaded as one. Set the actual public API base URL,
OAuth endpoints, OAuth client, and Meta-assigned callback during preview
onboarding. Register only the listed read operations as assistant tools; the
upload, unlink, deletion, and relink operations belong to the account/operator
workflow and must not be exposed as general Meta AI tools. The assistant needs
only `cf.audit.read`.

Deploy `factoryline.meta_connector_api:app` behind HTTPS with Gunicorn or a
compliant WSGI host. The single-worker image is in
`deploy/meta-connector/Dockerfile`; mount `/data` as a persistent, private
volume and terminate HTTPS at the ingress. Set `FACTORY_META_DATABASE` to a persistent private SQLite
path for that single-worker deployment. For Vercel Functions, set it to a
dedicated PostgreSQL DSN. The Vercel entrypoint at `api/index.py` removes the
`/api` mount prefix; Vercel rejects a local SQLite path rather than starting a
service with ephemeral account state. PostgreSQL transactions lock the account
row during bounded uploads, unlink, and relink so concurrent requests cannot
evade the account cap or revocation check. Set `FACTORY_META_PUBLIC_BASE_URL`
to the actual HTTPS base, including any `/api` or proxy prefix, so OpenAPI
advertises the correct server. Set `FACTORY_META_OIDC_ISSUER`, `FACTORY_META_OIDC_AUDIENCE`,
`FACTORY_META_JWKS_URL`, `FACTORY_META_AUTHORIZATION_URL`, and
`FACTORY_META_TOKEN_URL` to a real HTTPS OAuth2/OIDC provider. Configure that
provider's authorization-code + PKCE account-linking client for Meta's callback
URL after the preview onboarding UI reveals it. Its access tokens must be
RS256 JWTs with `tenant_id`, `sub`, `jti`, `groups` (string array), `scope`,
`iat`, and `exp` claims and no more
than a 15-minute lifetime. The service validates signature, issuer, audience,
time, account revocation, and read/write scope; it never accepts account IDs
from request paths or bodies as authority. Relink tokens additionally need an
`auth_time` claim from a fresh OAuth grant and the `cf.audit.link` scope.
The Clerk profile does not infer freshness from token `iat`: refresh tokens
can mint new access tokens without a new user authorization.

The external identity provider owns OAuth consent, refresh-token storage,
unlinking at the provider, and authorization-server operation. This repository
does not provide an authorization server. Meta's actual callback and required
scopes must be checked during authenticated onboarding before production use.

## Snapshot intake and limits

Upload a `factory.meta.audit.v1` JSON object with repository slug, exact Git
commit, policy SHA-256 (or `null` when the project review policy is absent),
timezone-aware creation time, all five lane outcomes,
up to 500 bounded findings, and explicit coverage notes. The importer must
derive those values from a current local CF/FL audit and state any incomplete
lanes honestly. The server caps bodies at 512 KiB, findings at 500, accounts
at 200 retained audits, and query pages at 50. Records expire from query
results after seven days. Operators must run a deletion job for expired rows;
expiry alone does not erase database bytes or backups.

The local Muse plugin supplies a bridge at
`plugins/muse-code-factory-audit/scripts/sync-meta-connector.mjs`. Run its
`. zrk222/code-factory --dry-run` form to inspect the exact payload. Pass
an HTTPS `/v1/audits` endpoint instead of `--dry-run` and provide a short-lived
`FACTORY_META_ACCESS_TOKEN` in the environment to upload. The bridge checks
the local receipt's HMAC, expiry, and current Git/policy snapshot. It exports
only bounded structured findings, never the raw scanner message. A local HMAC
does not make the hosted record an independently attested audit.

Repository content, raw voice, credentials, and build logs are outside this
summary contract. Clients should send concise finding labels and repair steps
only. Treat every submitted string as untrusted data in the Meta agent. Do not
follow instructions inside finding text.
When the project review policy is absent, the exporter records
`policy_sha256: null`, names the missing pattern and guard-path coverage, and
cannot report Code Factory as `PASS`.

## Launch gates

### Isolated Vercel route

Deploy the Code Factory repository as its own Vercel project. Use the Python
WSGI function at `api/index.py`, root `requirements.txt`,
and the root `vercel.json` exclusion list. Do not build Code Factory into the
WizeMe frontend or API bundle, reuse WizeMe's database, or share WizeMe's
OAuth secrets. Prefer a dedicated `cf.wizeme.app` subdomain assigned directly
to the connector project, with `/api` as the API path. This makes no change to
the WizeMe app or its edge routing. A path is not an authorization layer. Keep
the Vercel project URL available for independent smoke checks and rollback.

Before attaching a subdomain, verify a production-class connector with
its own database and OAuth issuer: health, readiness, OpenAPI, token rejection,
scoped read, upload, unlink/relink, cross-tenant isolation, and deletion. Use a
Vercel preview, compare key WizeMe route responses and latency against the
current production baseline, and reject promotion on any regression. The current
WizeMe source and deployment are deliberately unchanged.
Provider resources are provisioned separately from this spec; their readiness
must be established by live checks before production use.

Local tests and OpenAPI generation demonstrate an API implementation, not a
live HTTPS service, accepted OAuth link, Meta approval, or public listing.
Before submitting as a functioning connector, provision HTTPS hosting and a
real OAuth provider, verify account link/unlink and cross-account isolation in
Meta's guided test, publish service privacy/terms, and capture a live endpoint
read-back. Do not claim independent evidence verification or full-depth audit
from a submitted summary alone.

Meta's public early-access application accepts a REST API in active
development; that application was submitted on 2026-09-27 and is distinct from
a Muse Connector Platform directory submission. The signed-in Muse directory
form exposes Overview, Technical specs, and Review steps. The isolated Vercel
deployment, dedicated Neon database, verified production Clerk domain, and
read-only OAuth client are provisioned. Hosted health/readiness, OpenAPI, and
unauthenticated rejection have live read-backs. No Meta redirect URI has been
assigned, and live scoped read, upload, unlink/relink, and cross-account tests
remain. Public connector privacy/terms pages now return 200. The Muse Overview
and Technical specs forms are prepared; final terms acceptance, submission,
and the directory's own security/legal review remain outstanding. Do not call
an early-access application a live
directory submission or an approved connector.


# Isolated Vercel deployment for the Meta connector

This service is a Code Factory deployment, separate from WizeMe's frontend,
API, database, authentication application, and Vercel project. The preferred
public address is `https://cf.wizeme.app/api`. The `/api` path is a Vercel
function mount, not a security boundary. Bearer OAuth authorization protects
all account data.

## Deployment inputs

Create a dedicated Vercel project from the Code Factory repository root. The
project uses `api/index.py`, root `requirements.txt`, and root `vercel.json`.
Do not add a WizeMe source import, edge rewrite, or WizeMe secret to this
project. Do not assign `cf.wizeme.app` until the direct project URL passes the
checks below.

Set these values only in that project's environment secret manager:

| Variable | Required value |
| --- | --- |
| `FACTORY_META_DATABASE` | Dedicated PostgreSQL DSN, never WizeMe's database or local SQLite |
| `FACTORY_META_OIDC_ISSUER` | Dedicated OAuth/OIDC issuer HTTPS URL |
| `FACTORY_META_OIDC_PROVIDER` | `clerk` for the dedicated Clerk OAuth instance; omit for generic OIDC |
| `FACTORY_META_TENANT_ID` | Fixed `code-factory` tenant for dedicated Clerk instance |
| `FACTORY_META_CLERK_CLIENT_ID` | Exact Clerk OAuth client whose access tokens may call this API |
| `FACTORY_META_CLERK_CLIENT_SECRET` | That client's secret, used only for live token introspection |
| `FACTORY_META_AUTHORIZATION_URL` | Issuer's HTTPS authorization URL |
| `FACTORY_META_TOKEN_URL` | Issuer's HTTPS token URL |
| `FACTORY_META_PUBLIC_BASE_URL` | Final public API base URL, including `/api` |

For generic OIDC, instead set `FACTORY_META_OIDC_AUDIENCE` and
`FACTORY_META_JWKS_URL` as documented in `env.example`. The dedicated Clerk
profile verifies each OAuth access token through Clerk's `/oauth/token_info`
endpoint, requires the configured client ID and `cf.audit.read` scope, and
maps the dedicated instance to the fixed tenant. An inactive token fails
closed. Use authorization-code + PKCE with Meta's assigned callback. Keep
write scopes out of Meta's assistant tools. The Clerk profile does not
support self-service relink because its introspection response lacks
`auth_time`. Provision the database
and OAuth application as separate Code Factory resources. Confirm their
free-tier limits or obtain a budget before creation; an existing Vercel
subscription does not make extra provider usage free.

## Functional admission

1. On the direct project URL, check `/api/health`, `/api/ready`, and
   `/api/openapi.json`. The OpenAPI `servers[0].url` must exactly match the
   planned public base URL. An incomplete service must fail readiness.
2. Check that anonymous account/audit requests return 401, read-only tokens
   cannot upload or delete, and wrong-tenant requests cannot read a record.
3. Link a test account, upload one bounded summary, read its findings and
   coverage from a second function invocation, unlink, prove old access is
   rejected, and delete the account. In generic OIDC mode, also relink with
   fresh authorization. In Clerk mode, verify `RELINK_UNSUPPORTED`. Verify
   the database retains only the intended rows after each step.
4. Exercise concurrent uploads against the per-account limit and a concurrent
   unlink/upload race on the real PostgreSQL service. Local dialect tests do
   not prove database-level concurrency.
5. Assign `cf.wizeme.app` directly to the Code Factory project. Confirm DNS,
   TLS, OAuth redirect and issuer settings, and both direct and custom-domain
   read-backs. Keep WizeMe's production deployment unchanged.
6. Compare the status, response body marker, and latency distribution for
   WizeMe's homepage and key API routes before and after DNS attachment. Stop
   if any WizeMe route changes or latency materially regresses. This is a
   verification requirement, not a claim of measured zero impact.
7. Publish accurate Code Factory service privacy and terms pages, then inspect
   Meta's Technical specs and Review steps. Submit the directory listing only
   after the authenticated Meta end-to-end flow passes and any binding terms
   have been confirmed at action time.
