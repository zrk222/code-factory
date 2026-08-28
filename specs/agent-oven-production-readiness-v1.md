# Spec: agent-oven-production-readiness-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description
Give authenticated Agent Oven administrators a sanitized, server-owned go-live cockpit that distinguishes a working hosted control plane from complete enterprise operations. The cockpit shall explain missing activation work without returning environment-variable names, secret references, secret values, or identity claims.

### User roles
- Workspace administrator: reads the sanitized production-readiness explanation for one authorized workspace.
- Workspace viewer: remains unable to read deployment-level readiness.
- Platform operator: supplies environment configuration through Convex deployment tooling, outside the browser.

### Requirements (EARS)
- When `PRODUCTION_READINESS_EVALUATED` occurs, the server shall return exactly 7 evaluated controls: identity trust, application endpoint, billing webhook, transactional email, runtime worker, backup storage, and security contact.
- When a required value is absent, the server shall return marker `READINESS_CONTROL_MISSING`, status `missing` for its control, and one customer-safe next action.
- If a configured value violates its HTTPS, hostname, client-identifier, secret-reference, or email contract, the server shall return marker `READINESS_CONTROL_INVALID` and status `invalid` without returning the configured value.
- While identity trust and application endpoint are both ready, the server shall return marker `CONTROL_PLANE_READY` and `controlPlaneReady=true`.
- While all 7 controls are ready, the server shall return marker `ENTERPRISE_OPERATIONS_READY`, `enterpriseReady=true`, and overall status `ready`.
- While the control plane is ready and at least 1 enterprise operations control is not ready, the server shall return marker `PRODUCTION_PILOT_READY` and overall status `pilot`.
- If identity trust or application endpoint is not ready, the server shall return marker `PRODUCTION_ACTIVATION_BLOCKED` and overall status `blocked`.
- When an authenticated workspace administrator requests readiness, the Convex server shall return marker `PRODUCTION_READINESS_EXPLAINED` only after server-side role authorization.
- If a workspace viewer requests readiness, the Convex server shall return `E_ROLE_FORBIDDEN` before returning any readiness control.
- While readiness is returned to the browser, the server shall return marker `READINESS_RESPONSE_REDACTED` and exactly 0 environment-variable names, secret references, secret values, OIDC claims, or provider credentials.
- When the Operations surface renders, the browser shall return marker `PRODUCTION_COCKPIT_VISIBLE` after showing both control-plane and enterprise readiness, the 7 controls, and one plain-language next action for every non-ready control.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Explain a live pilot truthfully
  Given identity trust and application endpoint are ready
  And 4 secret-backed operations controls and security contact are missing
  When PRODUCTION_READINESS_EVALUATED occurs
  Then controlPlaneReady is true enterpriseReady is false and overall status is pilot

Scenario: Reject malformed configuration without disclosure
  Given the billing webhook value contains a raw token instead of an opaque reference
  When PRODUCTION_READINESS_EVALUATED occurs
  Then billing webhook is invalid and exactly 0 configured values are returned

Scenario: Protect deployment posture by role
  Given an authenticated workspace viewer
  When readiness is requested
  Then E_ROLE_FORBIDDEN is returned before any readiness control

Scenario: Render the go-live cockpit
  Given a workspace administrator and pilot readiness
  When the Operations surface renders at 390 and 1440 CSS pixels
  Then both readiness phases and all 7 controls are shown without horizontal overflow
```

## SHOULD - Technical/structural
- ADR reference: `adr/agent-oven-production-readiness-v1.md`.
- Data model: no table is required; evaluation uses server environment presence and validation only.
- API contract: `operations.productionReadiness({ workspaceId })` returns sanitized status metadata.
- UI contract: `ProductionActivationPanel` is rendered inside the existing Operations surface.

### Authorized bounded constants
- The readiness model contains exactly 7 controls and exactly 2 phases.
- Overall statuses are exactly `blocked`, `pilot`, and `ready`; control statuses are exactly `missing`, `invalid`, and `ready`.
- Secret-manager schemes are exactly `vault://`, `aws-sm://`, `azure-kv://`, and `gcp-sm://`.
- Browser proof widths are exactly 390 and 1440 CSS pixels.
- UI icons may use 14, 16, 18, and 22 CSS pixels; the layout uses 2 phase cards and 7 control rows.
- Validation commands time out after 180 seconds.
- The existing Operations module retains text bounds 80, 120, 240, 500, and 5000 characters; queue age conversion 1000; percentage cap 100; queue and failure warning thresholds 300 and 10; restore proof values 30 and 180; source freshness test values 3600 and 10800; and restore fixture suffix 001.
- The existing visual contract retains typography weights 400, 500, 600, 700, and 800.

## SHOULD NOT - Implementation details
- No browser route may read deployment environment values directly.
- No missing configuration may be represented as ready.
- No secret-manager reference may be resolved by the Convex control plane.
- No viewer may receive deployment readiness.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `PRODUCTION_READINESS_EVALUATED` exists | return exactly 7 evaluated controls |
| 2 | `READINESS_CONTROL_MISSING` exists | return status `missing` and one customer-safe next action |
| 3 | `READINESS_CONTROL_INVALID` exists | return status `invalid` and exactly 0 configured values |
| 4 | `CONTROL_PLANE_READY` exists | return `controlPlaneReady=true` |
| 5 | `ENTERPRISE_OPERATIONS_READY` exists | return `enterpriseReady=true` and overall status `ready` |
| 6 | `PRODUCTION_PILOT_READY` exists | return overall status `pilot` |
| 7 | `PRODUCTION_ACTIVATION_BLOCKED` exists | return overall status `blocked` |
| 8 | `PRODUCTION_READINESS_EXPLAINED` is absent after administrator request | block readiness success |
| 9 | `E_ROLE_FORBIDDEN` exists | return exactly 0 readiness controls |
| 10 | `READINESS_RESPONSE_REDACTED` is absent | block browser readiness response |
| 11 | `PRODUCTION_COCKPIT_VISIBLE` is absent after Operations render | block UI release |
