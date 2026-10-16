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
- If a mission criterion declares a deterministic native gate, the system shall verify a typed, current gate observation derived from that gate's native execution receipt and bind it to the mission, criterion, candidate, and source manifest; generic `passed` fields and evidence filenames shall not satisfy the gate, verified by `native_gate_receipts_bound`.
- The system shall distinguish executed checks, current proof reuse, source-integrity challenges and observed behavioral challenges without treating a planned run or infrastructure failure as behavioral evidence, verified by `execution_dispositions_grounded`.
- The system shall store normalized external review claims with provider/report/source provenance and reproduced, contradicted or unverified dispositions backed by evidence references, verified by `external_claims_grounded`.
- The system shall emit changed behavior, checked cases, unexamined scope, unfinished work, human review and one next action through existing mission and review surfaces, verified by `completion_summary_readable`.
### Acceptance criteria (Gherkin)
```gherkin
Scenario: inspect an agent-produced change
  Given a mission and current source-bound execution evidence
  When the developer inspects its completion summary
  Then each declared case shows its input digest, expected and observed outcome, and execution evidence
  Then every required deterministic gate has a typed current receipt bound to the mission, criterion, candidate, and source manifest
  Then missing or stale evidence appears as a named completion gap
  Then local execution, signer attestation, proof reuse, and behavioral challenges retain distinct dispositions
  Then normalized external review claims cite their provider, report, source, and supporting evidence
  Then the summary shows changed behavior, checked cases, unexamined scope, unfinished work, human review, and one next action
```
## SHOULD — Technical/structural
- Bound case and evidence collections using existing mission and proof limits; no additional provider client, daemon, scheduler or ledger.
- Preserve privacy-safe sharing separately from the local detailed summary.
- Reuse current receipts only after their existing candidate, dependency and environment verifiers pass.
- Derive unit, requirement-mutation and receipt-trace gate observations from the existing bounded local mutation capture and its pytest execution/catalog artifacts. Bind each observation to its gate criterion, mission, pre-capture case contract, candidate manifest and capture digests. Recompute these observations during read-only verification; never trust a caller-supplied gate `passed` boolean.
## SHOULD NOT — Implementation details
- Do not invent provider export formats, execute imported instructions, infer missing execution from an AI verdict, or add signing, merge, release or deployment authority.
- Do not claim lower false-positive rates, faster execution or production correctness without observed comparative evidence.
