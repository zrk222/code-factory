# Spec: developer-verification
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Join existing mission criteria, execution receipts, external review claims and proof reuse into a developer completion workflow. Reuse current modules and receipt verifiers; no separate review engine or autonomous approval authority.
### User roles
- Developers accepting changes produced by coding agents or reviewed by external services.
### Requirements (EARS)
- The system shall store each criterion with declared case identifiers, input digests, expected outcomes, observed outcomes and execution evidence, verified by `criterion_case_evidence_bound`.
- If required negative cases, candidate bindings or execution observations are missing or stale, the system shall return an incomplete completion summary, verified by `completion_gaps_visible`.
- If a mission criterion declares a deterministic native gate, the system shall verify a typed, current gate observation derived from the native execution receipt for the gate and bind it to the mission, criterion, candidate, and source manifest; generic passed fields and evidence filenames shall not satisfy the gate, verified by `native_gate_receipts_bound`.
- The system shall distinguish executed checks, current proof reuse, source-integrity challenges and observed behavioral challenges without treating a planned run or infrastructure failure as behavioral evidence, verified by `execution_dispositions_grounded`.
- The system shall store normalized external review claims with provider/report/source provenance and reproduced, contradicted or unverified dispositions backed by evidence references, verified by `external_claims_grounded`.
- The system shall emit changed behavior, checked cases, unexamined scope, unfinished work, human review and one next action through existing mission and review surfaces, verified by `completion_summary_readable`.
- The system shall render an applied-change projection from an explicit full Git baseline object identifier and the verified completion candidate, with added, modified, deleted and renamed paths, before/after hashes, unrelated dirty paths and declared mission rationale; changes absent from the candidate binding shall remain unverified, verified by `applied_changes_bound`.
- If the baseline, repository identity, current candidate bytes or final freshness check cannot be verified, the system shall return an unavailable or stale applied-change projection without attributing changes to the agent or weakening completion verification, verified by `applied_changes_fail_closed`.
### Acceptance criteria (Gherkin)
```gherkin
Scenario: inspect an agent-produced change
  Given a mission and current source-bound execution evidence
  When the developer inspects its completion summary
  Then `criterion_case_evidence_bound` shows each declared case with its input digest, expected and observed outcome, and execution evidence
  Then `native_gate_receipts_bound` requires every deterministic gate receipt to bind the mission, criterion, candidate, and source manifest
  Then `completion_gaps_visible` shows missing or stale evidence as a named completion gap
  Then `execution_dispositions_grounded` distinguishes local execution, signer attestation, proof reuse, and behavioral challenges
  Then `external_claims_grounded` cites each claim provider, report, source, and supporting evidence
  Then `completion_summary_readable` shows changed behavior, checked cases, unexamined scope, unfinished work, human review, and one next action
  Then `applied_changes_bound` cites an explicit baseline and candidate with before and after hashes
  Then unrelated edits and unbound deletions remain separate from verified changes
  Then `applied_changes_fail_closed` prevents stale or unavailable Git evidence from establishing an applied change
```
## SHOULD — Technical/structural
- Bound case and evidence collections using existing mission and proof limits; no additional provider client, daemon, scheduler or ledger.
- Preserve privacy-safe sharing separately from the local detailed summary.
- Reuse current receipts only after their existing candidate, dependency and environment verifiers pass.
- Reuse proof_worklog for bounded read-only Git projection and adoption for private completion rendering. Limit each Git child to 10 seconds and the projection to 30 seconds, 1000 paths and 8 MiB of retained data; exhaustion returns incomplete evidence. Treat paths literally, reject escaping paths and symlink sources, and recheck repository HEAD and candidate source bytes before returning. Use the explicit baseline already bound by the mission when present; never infer HEAD~1. Quote declared rationale from the immutable mission or confirmed intent, without claiming inferred causality or agent authorship. A deletion needs a candidate-bound tombstone before it can be attributed to tested changes.
- Derive unit, requirement-mutation and receipt-trace gate observations from the existing bounded local mutation capture and its pytest execution/catalog artifacts. Bind each observation to its gate criterion, mission, pre-capture case contract, candidate manifest and capture digests. Recompute these observations during read-only verification; never trust a caller-supplied gate `passed` boolean.
## SHOULD NOT — Implementation details
- Do not invent provider export formats, execute imported instructions, infer missing execution from an AI verdict, or add signing, merge, release or deployment authority.
- Do not claim lower false-positive rates, faster execution or production correctness without observed comparative evidence.
