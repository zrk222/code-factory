# Spec: Team Pilot readiness v1

Status: approved

## Intent

Turn the proposed Team Proof Hub into an operable, bounded **customer-managed
reference pilot** workflow. The workflow shall prove only that the local
selection and operating evidence is present and hash-bound. It shall never
accept a customer, activate a paid offer, provision access, process payment,
or claim a managed service.

## MUST - Functional core

### Data model

`factory.team-pilot-launch.v1` has these exact facts:

| Fact | Allowed value | Purpose |
| --- | --- | --- |
| `pilot_id` | lowercase hyphenated identifier, 2-63 characters | Names a bounded pilot receipt |
| `owner` | named person or operating role, 1-128 characters | Retains the activation decision |
| `partner_count` | integer from 1 through 3 | Enforces the initial design-partner cap |
| `governance` | `human_controlled` | Prohibits automatic commercial activation |
| `delivery_mode` | `customer_managed_reference`; `factory_managed` is rejected | Rejects a managed-service claim |
| `evidence` | exactly one hash-bound file for each required kind | Binds decision evidence to the receipt |
| `receipt_marker` | `TEAM_PILOT_READY_FOR_OWNER_REVIEW` | Says only that the owner may review the local evidence |
| `terminal_verdict` | `READY_FOR_OWNER_REVIEW` | Preserves the owner-review-only result |
| `failure_marker` | `E_TEAM_PILOT_SCHEMA`, `E_TEAM_PILOT_PARTNER_CAP`, `E_TEAM_PILOT_GOVERNANCE`, `E_TEAM_PILOT_DELIVERY_MODE`, `E_TEAM_PILOT_EVIDENCE_KIND`, `E_TEAM_PILOT_EVIDENCE_PATH`, `E_TEAM_PILOT_EVIDENCE_DIGEST`, `E_TEAM_PILOT_COMMERCIAL_BOUNDARY`, or `E_TEAM_PILOT_RECEIPT_INVALID` | Names the fail-closed reason |
| `manifest_state` | `valid` or `invalid` | Controls manifest rejection |
| `evidence_kind_state` | `valid` or `invalid` | Controls evidence-kind rejection |
| `evidence_path_state` | `valid` or `invalid` | Controls evidence-path rejection |
| `evidence_digest_state` | `valid` or `invalid` | Controls evidence-digest rejection |
| `commercial_boundary_state` | `valid` or `invalid` | Controls commercial-boundary rejection |
| `public_artifact_digest_prefix_length` | 12 characters | Names JSON, Markdown, and Mermaid artifacts without exposing a full digest in the filename |

The five required evidence kinds are `design_partner_selection`,
`deployment_security_review`, `data_retention_decision`,
`support_and_incident_owner`, and `commercial_terms_review`. Every evidence
file path is workspace-relative, names an existing regular file, and has an
exact lowercase SHA-256 digest. The existing commercial packaging contract must
remain human-controlled, `design_partner_only`, and `purchasable: false`.

### Requirements (EARS)

- When `REQ_TEAM_PILOT_MANIFEST` is evaluated, the system shall accept only an
  exact `factory.team-pilot-launch.v1` JSON object with a named owner, a
  one-through-three partner count, `human_controlled` governance,
  `customer_managed_reference` delivery, and exactly five required evidence
  kinds.
- When `REQ_TEAM_PILOT_EVIDENCE` is evaluated, the system shall reject paths
  outside the workspace, missing or duplicate evidence files, duplicate or
  unknown evidence kinds, and any SHA-256 digest mismatch before it emits a
  receipt.
- When `REQ_TEAM_PILOT_COMMERCIAL_BOUNDARY` is evaluated, the system shall reject a packaging contract that is not human-controlled, not `design_partner_only`, marked purchasable, or no longer `COMMERCIALIZATION_STAGED_NOT_SELLABLE`.
- When `REQ_TEAM_PILOT_READY` is true, the system shall emit a deterministic
  `TEAM_PILOT_READY_FOR_OWNER_REVIEW` receipt and public Markdown and Mermaid
  views when an explicit output directory is supplied.
- When `REQ_TEAM_PILOT_RECEIPT_VERIFY` is evaluated, the system shall reject a
  receipt whose canonical digest, evidence projection, views, marker, or
  no-authority boundary has changed.
- When `REQ_TEAM_PILOT_AUTHORITY` is evaluated, the system shall reject any
  payment, contracting, entitlement, customer acceptance, Marketplace
  activation, deployment, publication, credential, messaging, signing, or
  managed-service authority.

## Acceptance criteria

```gherkin
Scenario: A selected pilot has locally reviewable operating evidence
  Given an exact `factory.team-pilot-launch.v1` manifest
  And REQ_TEAM_PILOT_MANIFEST
  And five hash-bound evidence files for every required kind
  And REQ_TEAM_PILOT_EVIDENCE
  And a human-controlled, design-partner-only, not-purchasable packaging contract
  And REQ_TEAM_PILOT_COMMERCIAL_BOUNDARY
  When factory team-pilot readiness runs
  Then it emits TEAM_PILOT_READY_FOR_OWNER_REVIEW
  And REQ_TEAM_PILOT_READY
  And REQ_TEAM_PILOT_RECEIPT_VERIFY
  And REQ_TEAM_PILOT_AUTHORITY
  And it states that a named owner must activate anything externally

Scenario: A pilot cannot silently widen into a managed service
  Given a manifest with `delivery_mode` equal to `factory_managed`
  When factory team-pilot readiness runs
  Then it returns E_TEAM_PILOT_DELIVERY_MODE
  And it does not write a readiness receipt

Scenario: Tampered decision evidence cannot pass a later review
  Given a manifest whose evidence SHA-256 no longer matches its file
  When factory team-pilot readiness runs
  Then it returns E_TEAM_PILOT_EVIDENCE_DIGEST
  And it does not return READY_FOR_OWNER_REVIEW
```

## SHOULD - Structural contract

- New module: `factoryline/team_pilot.py`.
- Public commands: `factory team-pilot readiness` and `factory team-pilot verify`.
- Tests: `tests/test_team_pilot.py`.
- Operator guide: `docs/TEAM_PILOT_LAUNCH.md`.
- Governance classification: human-controlled. The local gate writes only an
  explicit receipt packet and cannot make external commercial decisions.

## Non-goals

- No checkout, payment processor, billing record, contract, invoice, trial,
  entitlement, provisioning, customer messaging, source collection, hosted
  tenant onboarding, managed runner, or Marketplace price action.
- No managed-service, SLA, compliance certification, SSO/SCIM, KMS, security,
  cost, or productivity claim.
- No automatic partner selection. The evidence can only bind a selection that a
  named human has already made.

## Decision logic

| # | If | Then |
| --- | --- | --- |
| 1 | `manifest_state` is `invalid` | return `E_TEAM_PILOT_SCHEMA` |
| 2 | `partner_count` is outside 1 through 3 | return `E_TEAM_PILOT_PARTNER_CAP` |
| 3 | `governance` is not `human_controlled` | return `E_TEAM_PILOT_GOVERNANCE` |
| 4 | `delivery_mode` is `factory_managed` | return `E_TEAM_PILOT_DELIVERY_MODE` |
| 5 | `evidence_kind_state` is `invalid` | return `E_TEAM_PILOT_EVIDENCE_KIND` |
| 6 | `evidence_path_state` is `invalid` | return `E_TEAM_PILOT_EVIDENCE_PATH` |
| 7 | `evidence_digest_state` is `invalid` | return `E_TEAM_PILOT_EVIDENCE_DIGEST` |
| 8 | `commercial_boundary_state` is `invalid` | return `E_TEAM_PILOT_COMMERCIAL_BOUNDARY` |
| 9 | `manifest_state`, `evidence_kind_state`, `evidence_path_state`, `evidence_digest_state`, and `commercial_boundary_state` are `valid` | return `TEAM_PILOT_READY_FOR_OWNER_REVIEW` only |
