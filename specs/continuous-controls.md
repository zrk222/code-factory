# Spec: continuous-controls
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Code Factory shall provide a local, deterministic continuous-controls plane for engineering teams. A versioned policy pack declares controls, provenance, forbidden behaviour, gates, tests, and evidence. The plane resolves parent packs, rejects unsafe weakening, evaluates supplied receipts after repository events, records drift, governs expiring exceptions, and emits one actionable review packet. It is an evidence coordinator; it does not execute arbitrary commands, approve releases, merge code, or publish to providers.

### User roles
- Policy author: writes a pack and its control definitions.
- Implementer/agent: changes code and supplies independently produced receipts.
- Approver: confirms a policy or exception; must be distinct from its author.
- Reviewer: reads the evaluation, Graph Ops chain, and remediation.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- The system shall accept `factory.policy-pack.v1` JSON with a pack id, semantic version, provenance kind, source hash, controls, author, and approval metadata.
- The system shall recognise exactly `human_confirmed`, `trusted_source`, `observed_production`, and `agent_proposed` provenance kinds, shall emit `ENFORCED` only for human-confirmed or trusted-source packs approved by a different person, and shall emit `ADVISORY` for all other packs.
- When a pack declares a parent, the system shall resolve the parent inside the workspace, verify its exact SHA-256, retain every inherited control, and expose inherited coverage by repository.
- If a child deletes an inherited control, lowers severity, widens a threshold, removes required evidence, changes a forbidden behaviour, or changes a gate/test without independent approval, the system shall fail closed with a deterministic `E_CONTROL_DELETED` or `E_CONTROL_WEAKENING` finding.
- When a merge, agent action, deployment, or working-tree evaluation is requested, the system shall compare the effective policy and supplied receipt hashes with the requested event and report `CLEAR`, `DRIFT`, or `BLOCKED` without executing the declared commands.
- The system shall create an exception only when it has a named owner, reason, exact scope, an expiry timestamp no more than the pack maximum (30 days by default) from issuance, an evidence hash, and an approver distinct from its author; an expired exception or an evidence-hash mismatch shall emit `E_EXCEPTION_EXPIRED` or `E_EXCEPTION_EVIDENCE_MISMATCH` and block.
- The system shall emit a Graph Ops chain in the order `intent → control → forbidden behavior → gate → test → receipt → decision`, with a tamper-evident digest.
- The system shall return one deterministic remediation for the first blocking control and shall render the same finding set as JSON, Markdown, and Mermaid dossier artifacts suitable for IDE or pull-request review.
- The system shall never grant release, merge, deployment, signing, credential, or provider authority as a result of a controls evaluation.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: approved inherited controls are enforced
  Given a trusted parent policy and a human-confirmed child policy with separate authorship and approval
  When the child is resolved and a valid passing evidence receipt is supplied
  Then the evaluation marks the inherited control passed, reports coverage, and emits a complete Graph Ops chain

Scenario: an agent cannot weaken a gate
  Given a parent control with a strict threshold
  When an agent-proposed child widens the threshold or declares a control deletion
  Then resolution fails closed with a deterministic weakening or deletion error

Scenario: event drift is visible
  Given a sealed baseline effective policy digest
  When a merge or deployment evaluation observes a changed policy or receipt hash
  Then the result is drift or blocked and includes one next action without running commands

Scenario: exception governance is bounded
  Given an enforced control and a named evidence file
  When an author creates a seven-day exception approved by a different person
  Then the exception is active, hash-bound, and scoped; an expired exception blocks the control
```

## SHOULD — Technical/structural
- ADR references: `specs/enterprise-enforcement-reference-v1.md`, `specs/enterprise-ops-control-plane-v1.md`.
- Data model: policy pack, resolved inheritance, evaluation, exception, fleet manifest, and dossier are versioned JSON records with canonical SHA-256 digests.
- API contract (interface): `load_policy_pack`, `evaluate_controls`, `create_exception`, `fleet_coverage`, `write_controls_dossier`, and `continuous_controls_projection` in `factoryline.continuous_controls`.
- Bounds: inheritance depth ≤8, scanned projection records ≤500, controls per pack ≤500, exceptions ≤500, and all paths must remain beneath the workspace root.

## SHOULD NOT — Implementation details
- The evaluator should not shell out, contact a provider, infer policy from agent prose, or treat a green build as approval.

## Declared facts

`policy_provenance_enforcing`, `approval_separated`, `parent_hash_valid`,
`inherited_controls_present`, `threshold_weakening`, `control_deletion`,
`fresh_receipt_valid`, `exception_active`, `exception_expired`, and
`evidence_drift`, and `blocking_findings_empty` are the facts consumed by the
decision table.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | `policy_provenance_enforcing` is false or `approval_separated` is false | classify controls as ADVISORY and emit no release claim |
| 2 | `parent_hash_valid` is false, `control_deletion` is true, or `threshold_weakening` is true | fail closed and emit the deterministic error code |
| 3 | `fresh_receipt_valid` is true | mark the control PASSED |
| 4 | `exception_active` is true | mark the control EXEMPT |
| 5 | `fresh_receipt_valid` is false, `evidence_drift` is true, or `exception_expired` is true | mark the control BLOCKED and return its single remediation |
| 6 | `blocking_findings_empty` is true | return READY_FOR_HUMAN_REVIEW and retain human release authority |
