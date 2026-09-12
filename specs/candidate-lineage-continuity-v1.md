# Spec: candidate-lineage-continuity-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Candidate continuity is a bounded, read-only release-review check. It binds
one current Oracle contract, one candidate digest, one self-hash-valid deep
audit receipt, and one graph-lineage receipt to a single manifest. It catches
mixed or stale evidence before a human relies on Graph Ops; it does not decide
whether the candidate is correct or authorize any action.

### User roles
- A developer or CI reviewer supplying local evidence.
- A human release reviewer consuming the continuity receipt.
- An agent may propose the manifest, but cannot change its authority or release
  decision through this verifier.

### Declared facts
- `manifest_exact`: the manifest has the exact schema, fields, and candidate digest.
- `oracle_current`: the Oracle contract and every bound source hash verify now.
- `evidence_integrity`: every evidence path, size, file digest, and receipt seal verifies now.
- `candidate_bound`: every deep-audit and graph-lineage receipt names the manifest candidate digest.
- `evidence_complete`: exactly the deep-audit and graph-lineage kinds are present.
- `authority_locked`: the manifest authority is `none` and every action flag is false.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- The system shall verify REQ_CANDIDATE_CONTINUITY using manifest_exact, oracle_current, evidence_integrity, candidate_bound, evidence_complete, and authority_locked; it shall return `CANDIDATE_LINEAGE_VERIFIED` only when all six facts are true, return a stable `E_CANDIDATE_LINEAGE_*` error otherwise, return `release_approval: false` with every authority flag false, and perform no execution, credential read, checkpoint mutation, repair, approval, merge, publication, deployment, signing, or provider contact. [R1]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: one candidate is continuously evidenced
  Given REQ_CANDIDATE_CONTINUITY with `manifest_exact` and a current Oracle contract and self-hash-valid deep-audit and candidate-bound graph receipts
  When a reviewer verifies the continuity manifest
  Then the result is CANDIDATE_LINEAGE_VERIFIED with release approval false

Scenario: graph evidence is from another candidate
  Given the manifest candidate digest differs from the graph lineage digest
  When continuity verification runs
  Then verification fails closed with a graph or mismatch error

Scenario: legacy graph evidence is used for strict continuity
  Given a structurally valid legacy graph receipt without candidate binding
  When continuity verification supplies the expected candidate digest
  Then verification fails closed with an unbound graph error

Scenario: an evidence file was changed after sealing
  Given a manifest records a different evidence file SHA-256
  When continuity verification runs
  Then verification fails closed with an evidence-integrity error

Scenario: an agent attempts to grant authority
  Given the manifest authority is not none
  When continuity verification runs
  Then verification fails closed and no action is authorized
```

## SHOULD — Technical/structural
- ADR references: existing Oracle Firewall and deep-audit review-only contracts.
- Data model: exact JSON manifest with candidate SHA-256, Oracle contract map,
  and 2–8 unique evidence rows.
- API contract: `verify_candidate_lineage(root, manifest_path)` and the
  `factory graph lineage-continuity` CLI command.

## SHOULD NOT — Implementation details
<!-- Leave the "how" to the plan/tasks unless it is a systemic invariant -->

## Decision logic (factory candidates)
<!-- Ordered business rules over extracted facts. specline handoff compiles
     these via HSF instead of letting agents improvise them. -->
| # | if | then |
|---|----|------|
| 1 | `manifest_exact` is false | return `E_CANDIDATE_LINEAGE_SCHEMA`; never verify |
| 2 | `oracle_current` is false | return `E_CANDIDATE_LINEAGE_ORACLE` |
| 3 | `evidence_integrity` is false | return an evidence error; no verified result |
| 4 | `candidate_bound` is false | return `E_CANDIDATE_LINEAGE_UNBOUND`; no verified result |
| 5 | `evidence_complete` is false | return `E_CANDIDATE_LINEAGE_INCOMPLETE`; no verified result |
| 6 | all declared facts are true | return verified continuity only; keep every action locked |
