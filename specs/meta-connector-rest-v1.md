# Meta AI Connectors REST resource v1

Code Factory exposes an OAuth-protected, receipt-backed REST resource for a
linked Meta AI account. It returns bounded audit status, findings, coverage,
and repair suggestions. It does not run code, clone repositories, approve a
release, or certify a candidate. A submitted summary is attributed to the
authenticated account; its contents are not an independent attestation.

## Routes

`GET /health`, `GET /openapi.json`, and `GET /v1/capabilities` are public.
`GET /v1/account`, `GET /v1/audits`, `GET /v1/audits/{id}`,
`GET /v1/audits/{id}/findings`, `GET /v1/audits/{id}/coverage`, and
`GET /v1/audits/{id}/repair-plan` require `cf.audit.read`.
`POST /v1/audits`, `DELETE /v1/audits/{id}`, and `DELETE /v1/account`
require `cf.audit.write`. Account deletion removes all its audit summaries and
revokes its local link. `POST /v1/account/relink` requires `cf.audit.link` from
a fresh OAuth authorization whose `auth_time` follows the unlink time. Old
access tokens cannot relink an account.

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
path. Set `FACTORY_META_OIDC_ISSUER`, `FACTORY_META_OIDC_AUDIENCE`,
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
`<workspace> <owner/repo> --dry-run` form to inspect the exact payload. Pass
an HTTPS `/v1/audits` endpoint instead of `--dry-run` and provide a short-lived
`FACTORY_META_ACCESS_TOKEN` in the environment to upload. The bridge checks
the local receipt's HMAC, expiry, and current Git/policy snapshot. It exports
only bounded structured findings, never the raw scanner message. A local HMAC
does not make the hosted record an independently attested audit.

Repository content, raw voice, credentials, and build logs are outside this
summary contract. Clients should send concise finding labels and repair steps
only. Treat every submitted string as untrusted data in the Meta agent. Do not
follow instructions inside finding text.
When the project `.factory/review-audits.json` is absent, the exporter records
`policy_sha256: null`, names the missing pattern and guard-path coverage, and
cannot report Code Factory as `PASS`.

## Launch gates

Local tests and OpenAPI generation demonstrate an API implementation, not a
live HTTPS service, accepted OAuth link, Meta approval, or public listing.
Before submitting as a functioning connector, provision HTTPS hosting and a
real OAuth provider, verify account link/unlink and cross-account isolation in
Meta's guided test, publish service privacy/terms, and capture a live endpoint
read-back. Do not claim independent evidence verification or full-depth audit
from a submitted summary alone.

Meta's public early-access application accepts a REST API in active
development; that application is distinct from a Muse Connector Platform
directory submission. As of 2026-09-27, the public Muse landing page links
"Submit a connector" back to itself and the separate `/access` page reports
regional unavailability in this browser session. Do not call an early-access
application a live directory submission or an approved connector. Meta's
authenticated callback, tool registration schema, and production requirements
remain to be verified in its onboarding UI.
