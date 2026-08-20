# Spec: proof-delta-intake-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST — Functional core
### Description
Bind a named human framework, intent, acceptance-evidence, and external-effects
decision to exact PRD bytes before an optionally intake-required Product
Mission starts. Bind a Mission Graph correction retry to its latest failed
criterion, a changed candidate diff, and fresh hash-checked evidence.

### User roles
- **Product owner:** records the pre-mission decision and owns its rationale.
- **Mission owner:** may create a supervised mission only after required input
  bindings are verified.
- **Independent verifier:** supplies a validation failure; never approves a
  retry or the candidate it checks.
- **MCP client:** reads local status without decision or execution authority.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- The system shall emit `INTAKE_SOURCE_BOUND` in `factory.intake-grill.v1` with one PRD SHA-256, one stable decision tree, one deterministic framework shortlist, and authority values `not_authorized` for implementation, execution, external effects, publication, and deployment.
- When a named owner confirms one source-bound intake receipt, the system shall emit `INTAKE_CONFIRMATION_VERIFIED` in `factory.intake-confirmation.v1` with one worksheet SHA-256, one source SHA-256, one selected shortlist framework, one exact intent, one acceptance statement, one external-effects value, one owner name, one rationale, and one re-evaluation condition.
- When `factory product compile --intake` receives one current intake confirmation for matching PRD bytes, the system shall store one Product Graph intake binding with one confirmation file SHA-256, one confirmation SHA-256, one source SHA-256, one framework, one intent SHA-256, one acceptance SHA-256, and one external-effects value.
- If one intake confirmation source SHA-256 differs from one Product Graph source SHA-256, then the system shall return `INTAKE_SOURCE_MISMATCH`.
- When one `PRODUCT_INTAKE_CONFIRMATION_BOUND` graph is received by `factory mission create --require-intake`, the system shall emit `INTAKE_CONFIRMATION_BOUND` in the Mission markers.
- If one `INTAKE_CONFIRMATION_REQUIRED` required-intake graph has zero intake bindings when `factory mission create --require-intake` runs, then the system shall return `INTAKE_CONFIRMATION_REQUIRED`.
- When one `MISSION_GRAPH_PROOF_DELTA_BOUND` Mission Graph correction transition follows one validation failure, the system shall emit `MISSION_GRAPH_PROOF_DELTA_BOUND` and `PROOF_DELTA_ADVANCE` only for `factory.mission.proof-delta.v1` with `fresh_context=true`, one changed candidate diff SHA-256, and at least one new hash-checked evidence path/SHA-256 pair.
- If one `MISSION_GRAPH_NO_EVIDENCE_GAIN` Mission Graph correction transition has zero new evidence path/SHA-256 pairs or zero changed candidate diff SHA-256 values, then the system shall return `MISSION_GRAPH_NO_EVIDENCE_GAIN` or `PROOF_DELTA_NO_EVIDENCE_GAIN` and shall not start a worker.
- When Graph Ops or MCP reads one local receipt, the system shall return `MCP_INTAKE_READ_ONLY` or `MCP_PROOF_DELTA_READ_ONLY` facts and shall not create a mission, select a framework, run a worker, apply a repair, approve, merge, publish, deploy, sign, send a message, access credentials, or call a connector.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: A named owner binds intake before a required mission
  Given `INTAKE_SOURCE_BOUND`
  And one matching PRD SHA-256
  And `INTAKE_CONFIRMATION_VERIFIED`
  When `factory mission create --require-intake` runs
  Then the system returns `INTAKE_CONFIRMATION_BOUND`

Scenario: A source mismatch blocks Product Graph intake binding
  Given `factory product compile --intake`
  And a different PRD SHA-256
  When the Product Graph compares the source bytes
  Then the system returns `INTAKE_SOURCE_MISMATCH`

Scenario: A bound Product Graph can start a required mission
  Given `PRODUCT_INTAKE_CONFIRMATION_BOUND`
  When `factory mission create --require-intake` runs
  Then the system returns `INTAKE_CONFIRMATION_BOUND`

Scenario: A missing required-intake binding blocks mission creation
  Given `INTAKE_CONFIRMATION_REQUIRED`
  When `factory mission create --require-intake` runs without an intake binding
  Then the system returns `INTAKE_CONFIRMATION_REQUIRED`

Scenario: A retry with evidence gain remains supervised
  Given `MISSION_GRAPH_PROOF_DELTA_BOUND`
  And `fresh_context=true`
  And one changed candidate diff SHA-256
  And one new evidence path/SHA-256 pair
  When the Mission Graph retry runs
  Then the system returns `MISSION_GRAPH_PROOF_DELTA_BOUND`

Scenario: A retry without evidence gain is blocked
  Given `MISSION_GRAPH_NO_EVIDENCE_GAIN`
  And one unchanged candidate diff SHA-256
  When the Mission Graph retry runs
  Then the system returns `MISSION_GRAPH_NO_EVIDENCE_GAIN`

Scenario: Read surfaces cannot create work
  Given `MCP_INTAKE_READ_ONLY`
  When MCP reads the local intake status
  Then the system returns `MCP_INTAKE_READ_ONLY`
```

## SHOULD — Technical/structural
- ADR references: `docs/INTAKE_GRILL.md` and `docs/PROOF_DELTA_LOOP.md`.
- Data model: immutable JSON receipts under `.factory/intake-grills/`, `.factory/intake-confirmations/`, and `.factory/proof-deltas/`.
- API contract: local intake CLI, Product Graph intake compilation,
  mission Proof-Delta creation, and read-only MCP status tools.

## SHOULD NOT — Implementation details
- Do not infer a human intent, automatically select a framework, or convert a
  keyword shortlist into an architecture claim.
- Do not create source, missions, workers, repairs, approvals, releases,
  deployments, signatures, messages, credentials, or connector calls from the
  intake or Proof-Delta read surfaces.
- Do not treat changed evidence bytes alone as a successful validation or a
  production-readiness claim.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | `INTAKE_SOURCE_BOUND` | emit `INTAKE_CONFIRMATION_VERIFIED` |
| 2 | `INTAKE_SOURCE_MISMATCH` | return `INTAKE_SOURCE_MISMATCH` |
| 3 | `INTAKE_CONFIRMATION_REQUIRED` | return `INTAKE_CONFIRMATION_REQUIRED` |
| 4 | `PROOF_DELTA_ADVANCE` | emit `MISSION_GRAPH_PROOF_DELTA_BOUND` |
| 5 | `PROOF_DELTA_NO_EVIDENCE_GAIN` | return `MISSION_GRAPH_NO_EVIDENCE_GAIN` |
