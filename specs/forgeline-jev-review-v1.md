# Spec: forgeline-jev-review-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Reuse Code Factory's JEV evidence validator for ForgeLine requirements, implementation, test-evidence and repair reviews. Advisory findings cite bound material and cannot change deterministic outcomes.

### User roles
- Operator configures the reviewer and authorizes provider-bound source transfer.
- Coding agent uses cited verification actions to repair the selected candidate.

### Requirements (EARS)
- When `FORGE_PROFILE_CHECK_REQUESTED` contains a profile outside `requirements`, `implementation`, `test_evidence`, and `repair`, the system shall return `FORGE_CONTEXT_INVALID` and invoke 0 reviewers. [R1]
- When `FORGE_CONTEXT_BOUNDS_CHECKED` contains more than 128 acceptance propositions, more than 512 evidence records, or more than 256000 UTF-8 JSON bytes, the system shall return `FORGE_CONTEXT_INVALID` and invoke 0 reviewers. [R2]
- When `FORGE_REVIEW_BOUND` is accepted, the system shall bind the profile, source hashes, criteria, deterministic result, explicit omissions, evidence IDs and rubric version into 1 canonical SHA-256 request digest. [R3]
- When `JEV_RESPONSE_VALIDATED` has a changed context hash, unknown evidence ID, missing claim, or unsupported label, the system shall return `JEV_REVIEW_INVALID` and retain the original deterministic result. [R4]
- When `JEV_GATE_RESULT_RECONCILED` labels every claim `SUPPORTED`, the system shall retain exactly the original deterministic gate result and grant 0 approval, repair execution, merge, publication or deployment authority. [R5]
- When `JEV_REVIEW_UNAVAILABLE` occurs through absent configuration or a reviewer exception, the system shall record an advisory fallback with 0 model-derived changes to gate outcomes. [R6]
- When `FORGE_SOURCE_CHANGED` occurs between context capture and result admission, the system shall reject the model assessment as `JEV_REVIEW_STALE` and retain the original deterministic result. [R7]
- When `FORGE_REVIEW_RECORDED` occurs, the system shall append 1 advisory observation to the existing ForgeLine receipt history with request/result digests and supplied provider usage; absent usage shall remain null. [R8]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: All four review profiles share the same validator
  Given FORGE_REVIEW_BOUND for requirements, implementation, test_evidence and repair
  When JEV_RESPONSE_VALIDATED cites the supplied evidence IDs
  Then 1 request digest binds each profile
  And every deterministic gate result is unchanged

Scenario: Invalid and oversized contexts cannot dispatch
  Given FORGE_PROFILE_CHECK_REQUESTED with an unsupported profile
  And FORGE_CONTEXT_BOUNDS_CHECKED with 129 acceptance propositions
  When context validation runs
  Then FORGE_CONTEXT_INVALID invokes 0 reviewers
  And 513 evidence records or 256001 bytes invoke 0 reviewers

Scenario: Unsupported model authority is rejected
  Given a deterministic failure and JEV_GATE_RESULT_RECONCILED with SUPPORTED claims
  When result admission runs
  Then the deterministic failure remains
  And approval, repair execution, merge, publication and deployment authority remain 0

Scenario: Stale and unavailable reviews cannot promote
  Given FORGE_SOURCE_CHANGED or JEV_REVIEW_UNAVAILABLE
  When result admission runs
  Then JEV_REVIEW_STALE or an advisory fallback retains the original deterministic result
  And FORGE_REVIEW_RECORDED appends 1 observation with absent usage null

Scenario: All claims and references are checked
  Given JEV_RESPONSE_VALIDATED with a changed context hash, unknown evidence ID, missing claim or unsupported label
  When result admission runs
  Then JEV_REVIEW_INVALID retains the original deterministic result
```

## SHOULD — Technical/structural
- Reuse the CF evidence packet validator and ForgeLine receipt store; add no second evaluator or ledger.
- Bind selected source material and supplied execution artifacts. Missing material remains an explicit omission rather than semantic proof.
- Keep model calls explicit; the default local ForgeLine review sends 0 provider requests.

## SHOULD NOT — Implementation details
- Do not replace the deterministic judge, add a mandatory CF-to-Forge dependency cycle, or treat model agreement as independent ground truth.
- Do not add a Python module or raise any existing source size or complexity budget.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | FORGE_CONTEXT_INVALID | return FORGE_CONTEXT_INVALID with 0 reviewers |
| 2 | FORGE_SOURCE_CHANGED | return JEV_REVIEW_STALE without admission |
| 3 | JEV_REVIEW_INVALID | return JEV_REVIEW_INVALID without promotion |
| 4 | JEV_REVIEW_UNAVAILABLE | record advisory fallback |
| 5 | JEV_RESPONSE_VALIDATED | record advisory observation and preserve deterministic result |
