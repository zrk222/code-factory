# Spec: agent-cloud-operator-lifecycle-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core

### Description

Advance the existing single-tenant PR Assurance slice with an operator lifecycle: immutable AgentSpec history, canonical export/import, non-destructive rollback, emergency pause/revoke, and secret-free references for OpenAI and Anthropic BYOK. This remains a supervised local/pilot surface and does not introduce Phase 2 multi-tenancy, hosted secrets, billing, or autonomous merge authority.

### User roles

- Builder: edits and imports an AgentSpec and configures secret references.
- Operator: exports, rolls back, pauses, resumes, or permanently revokes an AgentSpec.
- Reviewer: retains independent authority over approval-gated actions.

### Requirements (EARS)

- The system shall return `AGENT_SPEC_VERSIONED` after persisting an immutable snapshot for every AgentSpec version, including the initial seeded version.
- When a Builder saves or imports a valid AgentSpec, the system shall return `VERSION_HISTORY_APPEND_ONLY` after appending exactly 1 new version without deleting prior versions.
- When an Operator exports an AgentSpec, the system shall return `AGENT_SPEC_EXPORTED`, canonical JSON, and a 16-character prototype digest that excludes database identifiers and timestamps.
- When a Builder imports an exported AgentSpec, the system shall return `AGENT_SPEC_IMPORTED` after `IMPORT_DIGEST_MATCHED`, every field validation, unknown-key rejection, and semantic-value preservation.
- If an import digest is wrong, the system shall return `E_IMPORT_DIGEST_MISMATCH` because `IMPORT_DIGEST_MATCHED` is absent and before any write.
- If import JSON is malformed, the system shall return `E_INVALID_IMPORT` before any write.
- When an Operator rolls back to an existing historical version, the system shall return `AGENT_SPEC_ROLLED_BACK` after restoring the selected snapshot as exactly 1 new head version.
- If `ROLLBACK_VERSION_FOUND` is absent, the system shall return `E_VERSION_NOT_FOUND` before any AgentSpec write.
- When an Operator pauses an AgentSpec, the system shall return `AGENT_EMERGENCY_STOPPED` after `LIFECYCLE_ACTION_ALLOWED`, suspending the AgentSpec, blocking each pending run, rejecting each pending approval, and appending lifecycle audit and receipt evidence.
- When an Operator resumes a suspended AgentSpec, the system shall return `AGENT_RESUMED` after `LIFECYCLE_ACTION_ALLOWED` and activation.
- If an Operator requests resume for a permanently revoked AgentSpec, the system shall return `E_AGENT_REVOKED` because `REVOKED_STATE_FOUND` exists and before any AgentSpec write.
- When an Operator revokes an AgentSpec, the system shall return `AGENT_PERMANENTLY_REVOKED` after `LIFECYCLE_ACTION_ALLOWED`, permanently setting revoked status, and closing pending runs and approvals.
- If an AgentSpec status is not active, the system shall return `E_AGENT_NOT_ACTIVE` before run, gate, approval, receipt, or usage writes.
- When a Builder configures a provider reference, the system shall return `BYOK_REFERENCE_BOUND` after `RAW_SECRET_ABSENT` and `SECRET_SCHEME_ALLOWED` exist and an OpenAI or Anthropic reference uses an `env:`, `vault:`, `azure-key-vault:`, or `aws-secrets-manager:` scheme.
- If a BYOK value resembles a raw credential, the system shall return `E_RAW_SECRET_FORBIDDEN` because `RAW_SECRET_ABSENT` is absent and before storage.
- If a BYOK value uses an unapproved scheme, the system shall return `E_INVALID_SECRET_REF` because `SECRET_SCHEME_ALLOWED` is absent and before storage.
- The system shall return `SECRET_VALUES_ABSENT` after storing provider, label, secret reference, and status while returning exactly 0 provider secret values.
- When the operator surface renders at 390, 768, and 1440 CSS pixels, the system shall return `OPERATOR_CONTROLS_BOUND` after exposing lifecycle state, export/import, version history, rollback, emergency controls, and 2 provider connections without horizontal overflow or overlapping actions.
- The system shall return `CONVEX_ONLY_STACK` after proving exactly 1 application backend, Convex, exists in the application dependency and source trees.
- The system shall return `MEMORY_AUTHORITY_SEPARATED` after proving exactly 0 memory-content fields grant authority.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Version and export a specification
  Given 1 seeded AgentSpec at version 1
  When the Builder saves it once
  Then AGENT_SPEC_VERSIONED proves versions 1 and 2 exist
  And VERSION_HISTORY_APPEND_ONLY proves version 1 remains unchanged
  And AGENT_SPEC_EXPORTED returns canonical JSON with a 16-character digest

Scenario: Import without semantic drift
  Given AGENT_SPEC_EXPORTED
  When the Builder imports the canonical JSON with its matching digest
  Then IMPORT_DIGEST_MATCHED and the import schema validator pass
  And AGENT_SPEC_IMPORTED creates exactly 1 new head version
  And VERSION_HISTORY_APPEND_ONLY preserves every prior version
  And a second export has the same canonical semantic JSON

Scenario: Reject a forged import
  Given canonical AgentSpec JSON and a wrong digest
  When the Builder attempts import
  Then E_IMPORT_DIGEST_MISMATCH is returned and 0 new versions exist

Scenario: Reject malformed import JSON
  Given malformed AgentSpec JSON
  When the Builder attempts import
  Then E_INVALID_IMPORT is returned and 0 new versions exist

Scenario: Roll back without rewriting history
  Given versions 1, 2, and 3
  When the Operator rolls back to version 1
  Then ROLLBACK_VERSION_FOUND and AGENT_SPEC_ROLLED_BACK create version 4 with version 1 semantic values
  And VERSION_HISTORY_APPEND_ONLY preserves versions 1 through 3
  And versions 1 through 3 remain unchanged

Scenario: Emergency pause closes pending authority
  Given 1 active AgentSpec with 1 awaiting-approval run
  When the Operator pauses the AgentSpec with a reason
  Then LIFECYCLE_ACTION_ALLOWED and AGENT_EMERGENCY_STOPPED suspend the AgentSpec and block the run
  And its pending approval is rejected and lifecycle evidence is appended
  And E_AGENT_NOT_ACTIVE rejects a new run before related writes

Scenario: Resume a suspended specification
  Given AGENT_EMERGENCY_STOPPED exists
  When the Operator resumes the suspended AgentSpec
  Then LIFECYCLE_ACTION_ALLOWED and AGENT_RESUMED activate the AgentSpec

Scenario: Revocation is irreversible
  Given 1 active AgentSpec
  When the Operator revokes and then attempts to resume it
  Then LIFECYCLE_ACTION_ALLOWED and AGENT_PERMANENTLY_REVOKED are recorded
  And REVOKED_STATE_FOUND proves the permanent lifecycle state
  And E_AGENT_REVOKED rejects resume

Scenario: Store references, never raw BYOK secrets
  Given the pilot workspace
  When the Builder saves the configured OpenAI and Anthropic references
  Then RAW_SECRET_ABSENT and SECRET_SCHEME_ALLOWED pass
  And BYOK_REFERENCE_BOUND stores exactly 2 enabled provider references
  And SECRET_VALUES_ABSENT proves exactly 0 provider secret values are returned
  And raw values beginning with sk- are rejected before storage

Scenario: Reject unsafe credential inputs
  Given a raw credential and a reference with an unapproved scheme
  When the Builder attempts to configure each provider
  Then E_RAW_SECRET_FORBIDDEN rejects the raw credential before storage
  And E_INVALID_SECRET_REF rejects the unapproved scheme before storage

Scenario: Render operator controls
  Given the lifecycle dashboard query
  When browser verification renders at 390, 768, and 1440 CSS pixels
  Then OPERATOR_CONTROLS_BOUND has no horizontal overflow or overlapping actions

Scenario: Preserve backend and authority boundaries
  Given the complete application tree
  When release verification executes
  Then CONVEX_ONLY_STACK proves exactly 1 application backend
  And MEMORY_AUTHORITY_SEPARATED proves exactly 0 memory-content authority fields
```

## SHOULD — Technical/structural

- ADR reference: `adr/agent-cloud-operator-lifecycle-v1.md`.
- Data model: `agentSpecVersions` and `providerConnections` in `products/agent-cloud/app/convex/schema.ts`.
- API contract: typed Convex functions in `products/agent-cloud/app/convex/lifecycle.ts`.
- UI contract: `products/agent-cloud/app/src/components/OperationsPanel.tsx`.

### Authorized bounded constants

- Supported providers are exactly 2: `openai` and `anthropic`.
- Approved secret-reference schemes are exactly 4: `env`, `vault`, `azure-key-vault`, and `aws-secrets-manager`.
- AgentSpec export has exactly 7 semantic keys: name, repository, providerProfile, memoryMode, authorityMode, hardBudgetCents, and validators.
- Export JSON is limited to 5000 characters; a secret reference is limited to 240 characters; a lifecycle reason is limited to 500 characters.
- Validator arrays contain 1 through 8 items; each validator is limited to 120 characters.
- Repository and AgentSpec names are limited to 200 characters; provider connection labels are limited to 80 characters.
- Prototype digests are exactly 16 lowercase hexadecimal characters and are not digital signatures.
- Browser checks use 390, 768, and 1440 CSS pixels; primary targets are at least 44 CSS pixels high.
- Lifecycle controls use icon sizes 14, 16, 18, 20, 21, 22, and 24 CSS pixels.
- The existing shared application shell retains icon sizes 15, 17, and 27 CSS pixels, the `PROOF LINE 01` label, a 64-character commit-SHA input bound, and typography weights 400, 500, 600, 700, and 800.
- Test and browser commands time out after 120 seconds.

## SHOULD NOT — Implementation details

- No raw provider secret, OAuth token, personal access token, or secret-value form field.
- No Phase 2 tenant administration, OIDC, billing, production secret broker, or cross-tenant claim.
- No destructive version deletion or rollback that rewrites a historical record.
- No resume path for a revoked AgentSpec.
- No live provider or GitHub network call in this phase.
- No claim that a prototype digest or receipt fingerprint is a digital signature.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `IMPORT_DIGEST_MATCHED` is absent | reject with `E_IMPORT_DIGEST_MISMATCH` before writes |
| 2 | `ROLLBACK_VERSION_FOUND` is absent | reject with `E_VERSION_NOT_FOUND` before writes |
| 3 | `LIFECYCLE_ACTION_ALLOWED` and pause or revoke exist | close pending runs and approvals before returning success |
| 4 | `REVOKED_STATE_FOUND` exists and resume is requested | reject with `E_AGENT_REVOKED` |
| 5 | `RAW_SECRET_ABSENT` is absent | reject with `E_RAW_SECRET_FORBIDDEN` |
| 6 | `SECRET_SCHEME_ALLOWED` is absent | reject with `E_INVALID_SECRET_REF` |
| 7 | `AGENT_SPEC_VERSIONED` is absent after save | block success |
| 8 | `CONVEX_ONLY_STACK` is absent | block release |
| 9 | `MEMORY_AUTHORITY_SEPARATED` is absent | block action authorization |
