# Spec: trusted-core-policy-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Expose an explicit trusted-core defect policy without rewriting legacy diagnostic state or precision. Native supported defects block, incomplete source validation blocks, and unresolved review items stay visible without being presented as established defects. A nonblocking policy result is not a clean security or release approval.

### Requirements (EARS)
- When `POLICY_SELECTED` is absent, the system shall emit the existing legacy scan, receipt and exit behavior with 0 default policy changes. [R1]
- When `TRUSTED_CORE_SELECTED` requests trusted-core-v1, the system shall emit 1 policy decision regenerated from current captured sources and native tiers within 30 seconds of qualification; serialized or caller-supplied tier counts shall emit 0 trusted decisions. [R2]
- When `POLICY_SOURCE_INCOMPLETE` contains missing capture, invalid partition, source drift, pending coverage or unsupported report scope, the system shall reject policy admission with exit code 2 and 0 clean or release approvals. [R3]
- When `POLICY_SUPPORTED_DEFECT` has at least 1 current native supported defect, the system shall emit DEFECTS_PRESENT with exit code 1 while retaining every raw diagnostic and severity. [R4]
- When `POLICY_REVIEW_REQUIRED` has 0 supported defects and complete current source validation, the system shall emit NO_SUPPORTED_DEFECTS_REVIEW_REQUIRED with exit code 0, passed=false, clean=false and release_approved=false. [R5]
- When `POLICY_IDENTITY_CHANGED` alters the selected policy, model, source inventory or native tier evidence, the system shall reject stale decision reuse and emit a different decision binding with 0 checkpoint-authority transfers. [R6]
- When `POLICY_RENDERED` is requested, the system shall emit the same decision through CLI, JSON, action summaries and receipt fields within 30 seconds of qualification while preserving legacy raw/active and supported counts separately, with 0 accuracy-improvement claims inferred from reclassification. [R7]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Legacy behavior remains selected by default
  Given POLICY_SELECTED is absent
  When POLICY_RENDERED runs
  Then R1 and R7 preserve legacy outputs

Scenario: Current native evidence determines the opt-in policy
  Given TRUSTED_CORE_SELECTED is requested
  When POLICY_SUPPORTED_DEFECT contains one supported defect
  Then R2 and R4 emit exit code 1

Scenario: Unresolved review items do not imply a clean security result
  Given POLICY_REVIEW_REQUIRED contains zero supported defects
  When POLICY_RENDERED runs
  Then R5 emits exit code 0 and zero release approvals

Scenario: Missing or stale evidence cannot authorize a decision
  Given POLICY_SOURCE_INCOMPLETE or POLICY_IDENTITY_CHANGED
  When TRUSTED_CORE_SELECTED is requested
  Then R3 and R6 reject stale decision reuse
```

## SHOULD — Technical/structural
- Add `--defect-policy` with default legacy-v1 and explicit trusted-core-v1. Reject its use outside audit security before scanning.
- Centralize decisions beside the native finding-tier reducer; adapters consume the decision, not independent severity/count heuristics.
- Trusted admission requires a complete unique source inventory, current hash-checked captured bytes, native finding regeneration and partition validation. Rehashed JSON without source capture remains unverified.
- Recompute after tenant-contract and collection finalization, and bind the policy ID/digest plus source/tier evidence digest into the candidate and receipt. A caller-provided decision is replaced or rejected, never trusted.
- Initially support native bounded security scans. The isolated full-repository scope has no native workspace partition and must reject trusted-core with E_DEFECT_POLICY_SCOPE. Workspace-v2 support requires its own native checkpoint and policy-digest integration; until implemented it also rejects explicitly. No silent fallback.
- Keep source state and legacy action packets intact. Add a distinct selected-policy action summary and decision; default rendering is unchanged. Trusted rendering distinguishes supported defects, unresolved context and primitive observations, with no instruction to repair every unknown as an established defect.
- Release consumers retain separate approval authority. Policy exit zero means this selected defect policy does not block; it is not evidence of complete semantic coverage or release readiness.
- No production modules or dependencies are added. Test modified routes first, including forged supported tiers, stale captures, invalid policy IDs, incomplete inventory and default compatibility.

## SHOULD NOT — Implementation details
- Do not remove, demote or relabel original diagnostics to improve a percentage.
- Do not market the supported subset's rate as the unchanged legacy active rate.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | POLICY_SOURCE_INCOMPLETE | reject admission and return exit 2 |
| 2 | POLICY_SUPPORTED_DEFECT | retain raw diagnostics and return exit 1 |
| 3 | POLICY_REVIEW_REQUIRED | retain unresolved review queue and return exit 0 without approval |

## Consolidated implementation packet

The historical `plans/trusted-core-policy-v1.md` packet is retained here with its original task states and evidence boundary. Consolidation does not declare its tasks complete.

### Implementation packet: trusted-core-policy-v1
Spec: specs/trusted-core-policy-v1.md
Architect verdict: PASS

## Tasks (atomic — each independently shippable)
- [ ] T1 | slice=factoryline | files=factoryline/primitive_observation_binding.py,factoryline/audit_action_refs.py,tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k trusted_core_policy316 -q` | Regenerate and bind an opt-in central policy decision after native tier admission; preserve legacy output and reject forged or stale inputs.
- [ ] T2 | slice=factoryline | files=factoryline/review_audits.py,factoryline/cli_audit.py,tests/test_cli_bootstrap.py | verify=`python -m pytest tests/test_cli_bootstrap.py -k trusted_core_policy316 -q` | Capture current bounded sources for the selected policy and wire matching CLI, JSON, receipt and exit semantics; reject unsupported scopes.

## Evidence boundary
This is a policy and user-interpretation correction, not an accuracy gain. Keep the original actionable precision goal unmet until measured. Future fresh-cohort registration must explicitly name its primary policy and also report legacy raw/active rates, abstentions and true-positive retention.

ECC architecture review: `.factory/precision315/ecc-policy-plan.md`. Approval covers bounded native source regeneration, not implementation correctness or accuracy. Full-repository profiles explicitly reject this policy until their checkpoint integration is separately qualified.
