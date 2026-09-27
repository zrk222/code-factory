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
write and relink scopes out of Meta's assistant tools. Provision the database
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
   rejected, relink with fresh authorization, and delete the account. Verify
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

No Vercel project, database, OAuth application, DNS assignment, or Meta
directory listing is created by this document.
