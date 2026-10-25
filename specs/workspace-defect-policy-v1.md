# Spec: workspace-defect-policy-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Extend the explicit trusted-core policy to the native workspace security scan without changing the frozen study or treating an unresolved security review as clean.

### Requirements (EARS)
- When `WORKSPACE_LEGACY` is selected, the system shall emit legacy workspace output and checkpoint configuration with 0 policy fields added. [R1]
- When `WORKSPACE_TRUSTED` selects trusted-core-v1 on workspace-v2, the system shall emit 1 decision from the native current byte-bound partition, with 0 authority from deserialized decisions. [R2]
- When `WORKSPACE_INCOMPLETE` encounters pending files, invalid partition, missing sources, source errors or collection incompleteness, the system shall return exit 2, passed=false, clean=false and release_approved=false. [R3]
- When `WORKSPACE_DEFECT` has at least 1 native supported defect and complete coverage, the system shall return DEFECTS_PRESENT with exit 1 while retaining all raw diagnostics and severities. [R4]
- When `WORKSPACE_REVIEW` has 0 supported defects and complete coverage, the system shall return NO_SUPPORTED_DEFECTS_REVIEW_REQUIRED with exit 0 and passed=false, clean=false and release_approved=false. [R5]
- When `WORKSPACE_IDENTITY_CHANGED` changes policy or native model identity, the system shall reject checkpoint reuse with mismatched configuration and bind the new decision to current inventory, context and tier identities, with 0 clean or release approvals. [R6]
- When `WORKSPACE_RENDERED` renders CLI or JSON output, the system shall emit the same native decision and retain legacy metrics separately, add 0 production modules and dependencies, and finish focused qualification within 30 seconds or report incomplete. [R7]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Explicit workspace selection preserves default behavior
  Given WORKSPACE_LEGACY is selected
  When WORKSPACE_RENDERED runs
  Then R1 preserves legacy output and checkpoint identity

Scenario: Native supported findings block the selected policy
  Given WORKSPACE_TRUSTED selects trusted-core-v1
  When WORKSPACE_DEFECT has complete coverage and one supported defect
  Then R2 and R4 return exit 1

Scenario: Unknown findings stay visible without security approval
  Given WORKSPACE_REVIEW has complete coverage and zero supported defects
  When WORKSPACE_RENDERED runs
  Then R5 and R7 return exit 0 without approval

Scenario: Incomplete or mismatched evidence blocks admission
  Given WORKSPACE_INCOMPLETE has pending coverage
  When WORKSPACE_IDENTITY_CHANGED is evaluated
  Then R3 and R6 return exit 2 or reject checkpoint reuse
```

## SHOULD — Technical/structural
- Share the bounded policy's descriptor, result state semantics and evidence digest helpers. Preserve isolated-v1 rejection.
- Select policy before inventory/checkpoint work. Policy ID and current native tier descriptor enter workspace checkpoint configuration. Verify configuration again before storing a checkpoint.
- Decide inside the native scan invocation after partition validation and current-generation source verification. Never add a report-only API that turns rehashed JSON into source authority.
- Source accounting and semantic coverage remain separate. This selected policy result never changes semantic_coverage=INCOMPLETE or native_completion_receipt=false.
- Freeze all changed source and test hashes for qualification. The sealed Study318 snapshot and delivered packet stay unchanged. No accuracy claim follows from this policy extension.

## SHOULD NOT — Implementation details
- Do not suppress unresolved diagnostics, invent trust premises or alter labels.
- Do not widen architecture limits or add provider assumptions.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | WORKSPACE_LEGACY | emit legacy output |
| 2 | WORKSPACE_TRUSTED | regenerate native admission |
| 3 | WORKSPACE_INCOMPLETE | block with exit 2 |
| 4 | WORKSPACE_DEFECT | block with exit 1 |
| 5 | WORKSPACE_REVIEW | review required with exit 0 and no approval |
| 6 | WORKSPACE_IDENTITY_CHANGED | reject stale checkpoint |
| 7 | WORKSPACE_RENDERED | emit the selected policy decision |
