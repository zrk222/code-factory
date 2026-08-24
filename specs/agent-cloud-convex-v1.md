# Spec: agent-cloud-convex-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Build a full-stack PR Assurance control room for Code Factory Agent Cloud. React and TypeScript render the application; Convex is the exclusive application backend, database, realtime query, mutation, and action platform. The app demonstrates the product workflow without claiming production authentication, live GitHub writes, paid model invocation, or cryptographic receipt signing.

### User roles

- Builder: configures the PR Assurance AgentSpec and launches a bounded run.
- Reviewer: inspects gates, evidence, cost, and proposed action before approving or rejecting it.
- Admin: inspects memory provenance, provider routes, budgets, and audit history.

### Requirements (EARS)

- The system shall return marker `CONVEX_ONLY_STACK` only when package dependencies, application imports, environment-variable names, and deployment instructions contain zero Supabase integrations and include React, TypeScript, Vite, and Convex.
- The system shall return marker `PRODUCT_VIEWS_BOUND` only when Overview, Agent Builder, Runs, Evidence, Memory, and Settings views render inside one responsive application shell.
- The system shall return marker `CONVEX_SCHEMA_BOUND` only when workspaces, agentSpecs, providerRoutes, runs, gates, approvals, receipts, memories, and auditEvents use Convex schema validators and workspace indexes.
- When the seed mutation executes repeatedly, the system shall return marker `DEMO_SEED_IDEMPOTENT` after storing exactly one demo workspace and one PR Assurance AgentSpec.
- When a Builder saves PR Assurance configuration, the system shall return marker `AGENT_SPEC_PERSISTED` after storing repository, provider profile, memory mode, authority mode, hard budget cents, validators, version, and status through one Convex mutation.
- When estimated run cost is at most hard budget cost, the system shall return marker `BUDGET_ACCEPTED` before creating a run.
- If estimated run cost exceeds hard budget cost, the system shall return error code `E_BUDGET_EXCEEDED` and commit zero runs, gates, approvals, receipts, usage records, and audit events.
- When a Builder launches an accepted run, the system shall return marker `ASSURANCE_RUN_CREATED` after atomically storing one run, exactly six ordered gates, one pending approval, prototype receipt lineage, and audit events.
- When a Reviewer decides a pending approval with the stored action digest, the system shall return marker `APPROVAL_DECISION_BOUND` after atomically storing the decision, run state, decision receipt, and audit event.
- If an approval status is not pending, the system shall return error code `E_APPROVAL_ALREADY_DECIDED` and commit zero decision changes.
- If a submitted action digest differs from the stored approval action digest, the system shall return error code `E_ACTION_DIGEST_MISMATCH` and commit zero decision changes.
- When an Admin adds memory, the system shall return marker `MEMORY_PROVENANCE_BOUND` after storing source, purpose, provenance, confidence, retention days, subject, workspace, agent scope, and an untrusted-context label.
- The system shall return marker `MEMORY_AUTHORITY_SEPARATED` only when action authority reads exactly 4 Trust policy fields named authorityMode, agentStatus, approvalStatus, and actionDigest and reads 0 memory-content fields.
- When an Admin deletes an active memory record, the system shall return marker `MEMORY_TOMBSTONED` after storing the memory deletion timestamp, appending one deletion receipt, and excluding the deleted memory record from active-memory queries.
- The system shall return marker `EVIDENCE_CLASSIFIED` only when every model evaluation displays `heuristic` and every deterministic gate displays `proof-bearing`.
- The system shall return marker `PROTOTYPE_RECEIPTS_LABELED` only when every prototype receipt displays `unsigned` and zero prototype receipts display `cryptographically verified`.
- The system shall return marker `UI_STATES_BOUND` only when empty, loading, success, error, and blocked-budget states render through named components or test fixtures.
- The system shall return marker `RESPONSIVE_ACCESSIBLE_UI` only when keyboard navigation, visible focus, semantic controls, primary targets of at least 44 CSS pixels, and layouts at 390, 768, and 1440 CSS pixels pass automated checks.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Seed and display the PR Assurance workspace
  Given an empty Convex database
  When the seed mutation runs 2 times
  Then DEMO_SEED_IDEMPOTENT proves exactly 1 demo workspace and 1 PR Assurance AgentSpec exist

Scenario: Persist a bounded AgentSpec
  Given the demo workspace
  When the Builder saves a provider profile, authority mode, memory mode, validators, and a 450-cent budget
  Then AGENT_SPEC_PERSISTED returns the same canonical AgentSpec version

Scenario: Reject an over-budget run
  Given an AgentSpec with a 100-cent hard budget
  When the Builder launches a run estimated at 101 cents
  Then E_BUDGET_EXCEEDED is returned and 0 runs exist

Scenario: Launch an assurance run
  Given BUDGET_ACCEPTED
  When the Builder launches the PR Assurance run
  Then ASSURANCE_RUN_CREATED stores 1 run, 6 ordered gates, 1 pending approval, linked prototype receipts, and audit events

Scenario: Prevent approval replay and substitution
  Given 1 pending approval bound to an action digest
  When a Reviewer decides the approval and repeats the decision or substitutes the digest
  Then APPROVAL_DECISION_BOUND records the first decision
  And E_APPROVAL_ALREADY_DECIDED or E_ACTION_DIGEST_MISMATCH rejects the second decision

Scenario: Tombstone memory with evidence
  Given 1 active memory with MEMORY_PROVENANCE_BOUND
  When an Admin deletes the active memory
  Then MEMORY_TOMBSTONED excludes the record and appends 1 deletion receipt
  And MEMORY_AUTHORITY_SEPARATED proves action authority reads 4 Trust policy fields and 0 memory-content fields

Scenario: Render the product shell
  Given PRODUCT_VIEWS_BOUND
  When automated checks render at 390, 768, and 1440 CSS pixels
  Then RESPONSIVE_ACCESSIBLE_UI and UI_STATES_BOUND are proven

Scenario: Prove the Convex-only backend
  Given the complete application tree
  When the dependency and source validator executes
  Then CONVEX_ONLY_STACK and CONVEX_SCHEMA_BOUND are proven
```

## SHOULD - Technical/structural

- ADR references: `adr/agent-cloud-convex-v1.md`.
- Data model: `products/agent-cloud/app/convex/schema.ts`.
- API contract: typed Convex functions under `products/agent-cloud/app/convex/`.
- Design contract: `products/agent-cloud/app/DESIGN.md`.
- Memory and Trust remain logical modules and clean-room boundaries inside the app; they do not import WizeMe source.

### Authorized bounded constants

- The seed count is exactly 1 workspace and 1 AgentSpec after 2 calls.
- An assurance run contains exactly 6 gates.
- Budget tests use 100 and 101 cents; the editable example uses 450 cents.
- Viewport checks use 390, 768, and 1440 CSS pixels.
- Primary interactive targets have a minimum height of 44 CSS pixels.
- Confidence is an integer from 0 through 100; retention is an integer from 1 through 3650 days.
- Repository text is limited to 200 characters; memory content is limited to 2000 characters.
- Commit identifiers are limited to 64 characters and rendered with an 8-character short form; reviewer rationale is limited to 500 characters.
- The visual system uses Lucide icon sizes 15, 16, 17, 18, 20, 21, 22, 24, and 27 CSS pixels, and labels the illustrative conveyor as proof line 01.
- Prototype receipt fingerprints are 16 lowercase hexadecimal characters and are not digital signatures.
- Action authority reads exactly 4 named Trust policy fields and 0 memory-content fields.
- Test and smoke commands time out after 120 seconds.

## SHOULD NOT - Implementation details

- No Supabase fallback, compatibility layer, example, or optional provider.
- No provider keys or connector secrets in Convex documents or browser storage.
- No claim that prototype receipt fingerprints are digital signatures.
- No live GitHub or model-provider API calls in the demo flow.
- No B2C/C2C templates, billing, SSO/SCIM, Terraform, or autonomous merge in v1.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `BUDGET_ACCEPTED` is absent | reject run before database writes |
| 2 | `APPROVAL_DECISION_BOUND` exists | reject a repeated decision with `E_APPROVAL_ALREADY_DECIDED` |
| 3 | `APPROVAL_DECISION_BOUND` digest differs | reject with `E_ACTION_DIGEST_MISMATCH` |
| 4 | `MEMORY_TOMBSTONED` exists | exclude the memory from active recall |
| 5 | `MEMORY_AUTHORITY_SEPARATED` is absent | block action authorization |
| 6 | `EVIDENCE_CLASSIFIED` is absent | block evidence publication |
| 7 | `PROTOTYPE_RECEIPTS_LABELED` is absent | block receipt display |
