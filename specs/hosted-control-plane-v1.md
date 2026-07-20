# Spec: hosted-control-plane-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Provide a supervised hosted tenant lifecycle for platform operators and tenant
administrators. The lane creates tenants, stores per-tenant OIDC and role
configuration, records secret-manager references without secret values, binds
GitHub installations through a one-time state, exposes a tenant-scoped
read-only overview, and renders a read-only operator console.

### User roles
- `platform_admin`: create tenants and administer any explicitly selected tenant.
- `admin`: configure identity, role mappings, secret references, and installation state only for its verified tenant.
- `viewer`: read the overview and audit summary only for its verified tenant.
- GitHub installation callback: consume one unexpired one-time state; it has no general tenant authority.

### Requirements (EARS)
- The system shall return marker `TENANT_CREATED` only after a verified `platform_admin` principal whose bootstrap tenant claim is `*` creates a tenant. [REQ-HCP-TENANT]
- The system shall return marker `TENANT_BOUNDARY_ENFORCED` only after rejecting blank tenant ids, ids outside `[a-z0-9][a-z0-9-]{1,62}`, duplicate ids with different display names, and every cross-tenant administrative request before mutation. [REQ-HCP-BOUNDARY]
- The system shall return marker `OIDC_CONFIG_VERIFIED` only after an authorized administrator writes an HTTPS issuer, HTTPS JWKS URL, and non-empty audience; secret query strings and URL credentials shall be rejected. [REQ-HCP-IDENTITY]
- The system shall return marker `ROLE_MAPPING_BOUND` only after atomically replacing 1–50 unique non-empty directory groups mapped only to `viewer`, `operator`, `approver`, or `admin`. [REQ-HCP-ROLES]
- The system shall return marker `SECRET_REFERENCE_BOUND` only after accepting an `env://` reference with an uppercase environment name matching `[A-Z][A-Z0-9_]{1,126}` and storing no resolved value. [REQ-HCP-SECRETS]
- The system shall return marker `INSTALLATION_STATE_ISSUED` only after generating 32 random bytes, storing only its SHA-256 digest, binding it to the tenant and actor for exactly 600 seconds, and returning the plaintext state once. [REQ-HCP-STATE]
- The system shall return marker `INSTALLATION_BOUND` only after the GitHub setup callback supplies an unused state created no more than 600 seconds earlier and a positive installation id, then stores the binding and state consumption in one PostgreSQL transaction. [REQ-HCP-INSTALL]
- The system shall return marker `INSTALLATION_RACE_REJECTED` after rejecting every losing transaction with `E_INSTALLATION_TENANT` or `E_INSTALLATION_STATE` when an installation belongs to another tenant, a state is older than 600 seconds or already used, or two callbacks race. [REQ-HCP-RACE]
- The system shall return marker `ADMIN_ACTION_AUDITED` only after appending every successful administrative mutation to a tenant hash chain binding tenant, action, actor, resource, safe payload, previous hash, sequence, and timestamp. [REQ-HCP-AUDIT]
- The system shall return marker `CONTROL_RLS_BOUND` only after PostgreSQL RLS rejects rows outside transaction-local `factory.tenant_id` on identity, role mapping, secret-reference, and administrative-audit tables. [REQ-HCP-RLS]
- The system shall return marker `CONTROL_OVERVIEW_REDACTED` only when a verified `viewer`, `admin`, or `platform_admin` receives the selected tenant's identity status, role counts, installation ids, secret purposes, outbox counts, approval counts, and audit events with zero tokens, secret references, secret values, webhook payloads, or private keys. [REQ-HCP-OVERVIEW]
- The system shall return marker `CONTROL_CONSOLE_READ_ONLY` only when `/console` renders responsive empty, loading, success, and error states, keeps the supplied Bearer token in JavaScript memory only, and uses no cookies, `localStorage`, or `sessionStorage`. [REQ-HCP-CONSOLE]
- The system shall return marker `TENANT_IDENTITY_VERIFIED` only after selecting stored tenant identity configuration with the unverified tenant claim as a lookup hint and verifying RS256 signature, issuer, audience, tenant, expiry, and groups. [REQ-HCP-DYNAMIC-ID]
- The system shall return marker `DYNAMIC_WEBHOOK_SECRET_BOUND` only after resolving the bound tenant's `github_webhook` secret reference at request time and verifying HMAC before ingestion; a missing or unresolved reference shall fail closed. [REQ-HCP-DYNAMIC-SECRET]
- The system shall return marker `CONTROL_EVENTS_SECRET_FREE` only when operation events contain allowlisted fields and zero Bearer tokens, state plaintext, secret references, resolved secrets, JWTs, webhook bodies, or GitHub private keys. [REQ-HCP-REDACTION]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Platform administrator onboards one tenant
  Given a verified platform_admin principal with the required bootstrap tenant claim
  When it creates a valid tenant, stores valid OIDC configuration, stores one allowed role mapping and secret reference, and issues installation state
  Then the GitHub callback consumes the state once and stores the positive installation binding
  And every successful mutation is present in one valid tenant hash chain

Scenario: Cross-tenant administrator is denied
  Given a verified admin principal for one tenant
  When it attempts to configure a different tenant
  Then the response is forbidden with the declared tenant-boundary error
  And no control row or audit event is created for the different tenant

Scenario: Installation state cannot be replayed
  Given an installation state with the declared lifetime issued for one tenant
  When one callback consumes the state and a second callback repeats it
  Then the first response contains the declared installation marker
  And the second response is a conflict with the declared installation-state error

Scenario: Read-only console protects authority
  Given the operator console is rendered on a mobile or desktop viewport
  When an operator loads tenant overview with an in-memory Bearer token
  Then the page exposes no mutation control
  And the source contains no cookie, localStorage, sessionStorage, deploy, credential, or secret-value authority

Scenario: Every hosted control-plane requirement has executable evidence
  Given the hosted control-plane smoke contract
  When hostile, PostgreSQL, identity, API, architecture, and console checks pass
  Then TENANT_CREATED and TENANT_BOUNDARY_ENFORCED are proven
  And OIDC_CONFIG_VERIFIED and ROLE_MAPPING_BOUND are proven
  And SECRET_REFERENCE_BOUND and INSTALLATION_STATE_ISSUED are proven
  And INSTALLATION_BOUND and INSTALLATION_RACE_REJECTED are proven
  And ADMIN_ACTION_AUDITED and CONTROL_RLS_BOUND are proven
  And CONTROL_OVERVIEW_REDACTED and CONTROL_CONSOLE_READ_ONLY are proven
  And TENANT_IDENTITY_VERIFIED and DYNAMIC_WEBHOOK_SECRET_BOUND are proven
  And CONTROL_EVENTS_SECRET_FREE is proven
```

## SHOULD — Technical/structural
- ADR references: `docs/HOSTED_CONTROL_PLANE.md`, `docs/HOSTED_PR_ASSURANCE.md`.
- Data model: PostgreSQL tenant, identity, role, secret-reference, installation-state, installation, outbox, approval, and hash-linked audit tables.
- API contract: WSGI routes under `/v1/admin/*`, `/v1/github/installations/callback`, and `/console`.
- Governance: `supervised`; administrative mutations require verified human authority and the GitHub callback is bounded to one state transition.

## SHOULD NOT — Scope boundaries
- Do not implement SCIM, SAML enrollment, billing, managed KMS, managed HA, disaster recovery, SOC 2 certification, or an SLA.
- Do not store OIDC tokens, GitHub private keys, webhook secret values, or installation state plaintext.
- Do not grant the console mutation, deployment, credential, connector, or release authority.
