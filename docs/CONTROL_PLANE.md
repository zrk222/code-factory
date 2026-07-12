# Control-Plane Foundation

FactoryLine 0.10 adds a local-first evidence and approval boundary. It is
useful today for a single repository and is intentionally small enough to
inspect, test, and export. It is not a hosted control plane, an identity
provider, or an SSO/SCIM implementation.

## What it guarantees

- Evidence is immutable by evidence id and bound to a tenant id.
- Reads, writes, lists, approvals, and audit verification are deny-by-default.
- A principal cannot cross a tenant boundary unless it is an explicitly scoped
  `platform_admin` with tenant `*`.
- Approval requires a separate principal and a non-empty reason.
- Audit events are hash-linked independently per tenant and can be verified
  without a network call.

## Five-minute local example

```powershell
factory control init --db .factory/control.sqlite3
factory control evidence-put receipts/build.json `
  --db .factory/control.sqlite3 --tenant acme --subject ci-runner --roles operator
factory control evidence-list --db .factory/control.sqlite3 `
  --tenant acme --subject auditor --roles viewer
factory control approval-request <evidence-id> `
  --db .factory/control.sqlite3 --tenant acme --subject ci-runner `
  --roles operator --reason "release candidate review"
factory control approval-decide <approval-id> `
  --db .factory/control.sqlite3 --tenant acme --subject release-manager `
  --roles approver --decision approved --reason "independent review complete"
factory control audit-verify --db .factory/control.sqlite3 `
  --tenant acme --subject auditor --roles viewer
```

For local integration testing, the same contract is available as a WSGI REST
adapter:

```powershell
factory control serve --db .factory/control.sqlite3 --host 127.0.0.1 --port 8765
```

The adapter exposes `GET /healthz`, evidence and approval routes under
`/v1/`, and `GET /v1/audit`. It requires `X-Factory-Subject`,
`X-Factory-Tenant`, and `X-Factory-Roles` headers. Those headers are an
explicit adapter boundary, not authentication: a production deployment must
verify OIDC/SSO or SCM credentials before constructing them.

The command returns structured JSON. A denied request returns a non-zero exit
and an error code such as `E_TENANT_BOUNDARY`, `E_ACTION_DENIED`, or
`E_SELF_APPROVAL`.

## Adapter boundary

Future hosted adapters may map OIDC/SAML identities, SCM webhook claims, or
service-account credentials into `Principal`. They must call the same
authorization and store methods; they must not bypass tenant checks or infer
approval from evidence ingestion. SSO/SCIM, GitHub/GitLab/Azure DevOps apps,
network service hardening, and external key management remain later
control-plane work.
