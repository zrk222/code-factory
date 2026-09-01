# Spec: atomic-proof-adapter-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Borrow Atomic's critical workflow mechanics in a local, evidence-only Code
Factory bridge: typed stage DAGs, scoped intercom handoffs, checkpoint-resume
continuity, and immutable artifact/source preconditions. The bridge binds an
exported Atomic workflow run to Code Factory's sealed Oracle Contract and
makes every mechanism inspectable in Graph Ops and MCP without running Atomic,
accepting a provider identity, or turning an agent-runtime receipt into release
authority.

### User roles
- **Atomic operator:** exports a bounded, secret-free Atomic run envelope and
  needs a deterministic answer to whether it is tied to the approved intent
  and permitted scope.
- **Reviewer:** needs Graph Ops to show the declared workflow, each stage
  checkpoint, handoff, evidence hash, and any reason the run cannot support
  promotion.
- **Agent author:** can read the imported result through MCP, but cannot use
  it to execute Atomic, alter the Oracle Contract, approve work, or release a
  change.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- The system shall return `E_ATOMIC_ENVELOPE_SCHEMA` with marker `ATOMIC_INPUT_REJECTED` before output when an input is not one bounded workspace-relative `factory.atomic-run-envelope.v1` with workflow, typed stages, SHA-256 references, scope paths, contract path, agent identity, handoffs, checkpoints, artifacts, and source preconditions.
- The system shall return `E_ATOMIC_PRIVATE_FIELD` with marker `ATOMIC_INPUT_REJECTED` before output when an envelope includes raw prompts, tool output, credentials, source bodies, network URLs, an unknown field, non-canonical JSON, an input over 1 MiB, or a path outside the workspace.
- When `ATOMIC_BINDING_SUBMITTED` supplies a current sealed Oracle Contract whose digest exactly matches an explicit declared DAG, the system shall write `ATOMIC_RUN_BOUND` as one immutable `factory.atomic-proof-adapter.v1` receipt under `.factory/atomic/` with hashes, safe identifiers, workspace paths, and declared lifecycle facts only.
- When `ATOMIC_SCOPE_SUBMITTED` contains a completed stage path outside the sealed Oracle Contract, the system shall return `E_ATOMIC_SCOPE_ESCAPE` before writing a receipt.
- When `ATOMIC_EVIDENCE_SUBMITTED` contains a missing artifact hash, checkpoint hash, tool-manifest hash, unbound handoff, unknown topology, or cyclic topology, the system shall return `E_ATOMIC_EVIDENCE_UNVERIFIED` before writing a receipt.
- When `ATOMIC_HANDOFF_BOUND` is requested with `ATOMIC_HANDOFF_SUBMITTED` facts naming a sender stage, receiver stage, capability, scope, contract digest, source snapshot hash, artifact hash, and tool-manifest hash that exactly match the declared workflow, the system shall retain the hash-only handoff relation in `ATOMIC_RUN_BOUND`.
- When `E_ATOMIC_HANDOFF_DRIFT` is detected after `ATOMIC_HANDOFF_SUBMITTED` changes a source snapshot, artifact hash, tool-manifest hash, stage capability, or approved scope, the system shall return `E_ATOMIC_HANDOFF_DRIFT` before writing a receipt.
- When `ATOMIC_CONTRACT_SUBMITTED` lacks a current Oracle Contract or contains a contract-digest mismatch, the system shall return `E_ATOMIC_UNBOUND_INTENT` before writing a receipt.
- When `ATOMIC_RESUME_SUBMITTED` reuses a run and checkpoint identity with a different checkpoint hash, workflow digest, contract digest, or tool-manifest hash, the system shall return `E_ATOMIC_RESUME_DIVERGENCE` before writing a receipt and set `recovery_action=human_reviewed_fork`.
- When `E_ATOMIC_STAGE_IDENTITY_UNPROVEN` is detected because `ATOMIC_HANDOFF_SUBMITTED` omits the contract digest or names an unknown stage, the system shall return `E_ATOMIC_STAGE_IDENTITY_UNPROVEN` before writing a receipt.
- While Graph Ops, MCP, or WebMCP reads imported Atomic facts, the system shall return `ATOMIC_MCP_READ_ONLY` with execution, approval, repair, publication, deployment, signing, messaging, credential, and connector authority false.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: an Atomic run is contract-bound before it becomes evidence
  Given a sealed Oracle Contract and an Atomic envelope accepted as ATOMIC_BINDING_SUBMITTED
  When the operator imports the envelope
  Then the bridge writes ATOMIC_RUN_BOUND with the exact contract, workflow, stage, artifact, and checkpoint hashes
  And it does not execute Atomic or grant a release decision

Scenario: a checkpoint resume diverges from the sealed run
  Given a completed Atomic run receipt with checkpoint cp-1
  And a resumed envelope that reuses cp-1 with a different checkpoint hash
  When the operator imports the resumed envelope
  Then the bridge returns E_ATOMIC_RESUME_DIVERGENCE
  And no successor receipt is written

Scenario: a stage tries to cross the approved scope
  Given a sealed Oracle Contract limited to src/checkout
  And an Atomic envelope submitted as ATOMIC_SCOPE_SUBMITTED with a completed stage declaring src/admin
  When the operator imports the envelope
  Then the bridge returns E_ATOMIC_SCOPE_ESCAPE before writing a receipt

Scenario: an intercom handoff cannot drift from its exact stage evidence
  Given an imported Atomic envelope with a scoped sender-to-receiver handoff
  And a changed source snapshot hash for the same handoff identity
  When the operator imports the envelope
  Then the bridge returns E_ATOMIC_HANDOFF_DRIFT before writing a receipt

Scenario: MCP remains a read-only observer
  Given a hash-valid imported Atomic receipt
  When an MCP client reads Atomic status
  Then it returns ATOMIC_MCP_READ_ONLY
  And every external or execution authority remains false

Scenario: every Atomic bridge rule has an explicit acceptance outcome
  Given an E_ATOMIC_ENVELOPE_SCHEMA input
  And an E_ATOMIC_PRIVATE_FIELD input
  And an ATOMIC_BINDING_SUBMITTED envelope
  And an ATOMIC_SCOPE_SUBMITTED envelope
  And an ATOMIC_EVIDENCE_SUBMITTED envelope
  And an ATOMIC_CONTRACT_SUBMITTED envelope
  And an ATOMIC_RESUME_SUBMITTED envelope
  And an ATOMIC_HANDOFF_BOUND request
  And an E_ATOMIC_HANDOFF_DRIFT finding
  And an E_ATOMIC_STAGE_IDENTITY_UNPROVEN finding
  When the bridge validates the bounded Atomic evidence
  Then it returns E_ATOMIC_ENVELOPE_SCHEMA
  And it returns E_ATOMIC_PRIVATE_FIELD
  And it returns ATOMIC_RUN_BOUND
  And it returns E_ATOMIC_SCOPE_ESCAPE
  And it returns E_ATOMIC_EVIDENCE_UNVERIFIED
  And it returns E_ATOMIC_UNBOUND_INTENT
  And it returns E_ATOMIC_RESUME_DIVERGENCE
  And it returns ATOMIC_HANDOFF_BOUND
  And it returns E_ATOMIC_HANDOFF_DRIFT
  And it returns E_ATOMIC_STAGE_IDENTITY_UNPROVEN
  And it returns ATOMIC_MCP_READ_ONLY
```

## SHOULD — Technical/structural
- ADR references: `docs/ORACLE_FIREWALL.md`, `docs/GRAPH_OPS.md`, and
  `docs/ATOMIC_PROOF_ADAPTER.md`.
- Data model: immutable envelope input plus one immutable adapter receipt
  under `.factory/atomic/`; both are bounded to 1 MiB and canonical JSON.
- API contract: Python `import_atomic_run`, CLI `factory atomic import|status`,
  MCP `factory.atomic_status`, WebMCP `factory.atomic_status`, and a Graph Ops
  projection. No Atomic runtime dependency is introduced.

## SHOULD NOT — Implementation details
<!-- The adapter must not import Atomic, execute an agent, infer a workflow's
runtime branches, read credentials, store prompts, trigger a checkpoint resume,
approve work, or claim that imported evidence proves Atomic's real-world
identity or execution. A TypeScript workflow is represented only by the
exporter's declared, hash-bound topology. -->

## Decision logic (factory candidates)
<!-- Ordered business rules over extracted facts. specline handoff compiles
     these via HSF instead of letting agents improvise them. -->
| # | if | then |
|---|----|------|
| 1 | `ATOMIC_INPUT_REJECTED` | return `ATOMIC_INPUT_REJECTED`, no output |
| 2 | `ATOMIC_CONTRACT_SUBMITTED` lacks a current matching contract | return `E_ATOMIC_UNBOUND_INTENT`, no output |
| 3 | `ATOMIC_EVIDENCE_SUBMITTED` is incomplete or non-DAG | return `E_ATOMIC_EVIDENCE_UNVERIFIED`, no output |
| 4 | `ATOMIC_SCOPE_SUBMITTED` escapes contract scope | return `E_ATOMIC_SCOPE_ESCAPE`, no output |
| 5 | `ATOMIC_HANDOFF_SUBMITTED` changes bound handoff evidence | return `E_ATOMIC_HANDOFF_DRIFT`, no output |
| 6 | `ATOMIC_RESUME_SUBMITTED` changes bound evidence | return `E_ATOMIC_RESUME_DIVERGENCE`, no output |
| 7 | `ATOMIC_BINDING_SUBMITTED` verifies | write `ATOMIC_RUN_BOUND` evidence-only receipt |
