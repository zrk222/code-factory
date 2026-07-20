# Hosted PR assurance

The hosted adapter turns the local authenticated PR-assurance core into a
deployable service without trusting caller-supplied tenant headers.

## Install

```bash
python -m pip install "factoryline-code-factory[hosted]"
```

Run behind a TLS-terminating load balancer:

```bash
gunicorn --workers 2 --threads 4 --bind 0.0.0.0:8080 \
  'factoryline.hosted_api:create_hosted_app_from_env()'
```

## Required configuration

| Variable | Purpose |
|---|---|
| `FACTORY_DATABASE_URL` | PostgreSQL DSN supplied by the secret manager |
| `FACTORY_OIDC_ISSUER` | Exact issuer pinned during JWT verification |
| `FACTORY_OIDC_AUDIENCE` | Exact API audience |
| `FACTORY_JWKS_URL` | Credential-free HTTPS JWKS endpoint |
| `FACTORY_ROLE_MAP_JSON` | Bootstrap directory group to Code Factory role map |
| `FACTORY_WEBHOOK_SECRETS_JSON` | Optional legacy installation-to-webhook-secret map |
| `FACTORY_INSTALLATION_TENANTS_JSON` | Optional legacy installation-to-tenant map |
| `FACTORY_GITHUB_APP_ID` | GitHub App numeric id |
| `FACTORY_GITHUB_PRIVATE_KEY` | PEM key injected by the secret manager |

When supplied, the two legacy installation maps must contain identical keys.
Startup applies the idempotent assurance and control schemas and confirms every
legacy mapping without permitting reassignment. New tenants should use the
[hosted control-plane lifecycle](HOSTED_CONTROL_PLANE.md).
Production operators should normally run migrations with a dedicated schema
role, then run the service with a restricted application role.

## Routes

- `GET /healthz`: process liveness only.
- `GET /readyz`: PostgreSQL plus usable JWKS readiness.
- `POST /v1/github/webhooks`: GitHub HMAC webhook ingress.
- `POST /v1/approvals/{approval_id}/decision`: OIDC Bearer approval.
- `POST/PUT/GET /v1/admin/...`: supervised tenant onboarding and overview.
- `POST /v1/github/installations/callback`: one-time installation binding.
- `GET /console`: read-only operator console.

Approval writes and GitHub Check outbox insertion share one PostgreSQL
transaction. A worker publishes pending rows using short-lived GitHub App
installation credentials. Publication failures retain a classified outbox
record; they do not roll back the already-audited human decision.

## Security and operating limits

- PostgreSQL tenant tables enable and force RLS with a transaction-local tenant.
- JWKS refresh uses HTTPS, a five-second timeout, no redirects, a five-minute
  fresh lifetime, and a fifteen-minute hard stale limit.
- GitHub App JWTs live for ten minutes or less. Installation tokens and private
  keys never enter API responses or structured operation events.
- The worker claims rows with `FOR UPDATE SKIP LOCKED` and stops automated
  attempts after 25 failures.
- The reference is deployable but does not claim HA, automatic disaster
  recovery, SCIM, SOC 2, or a managed service SLA. Those remain operator and
  hosting-platform responsibilities.
