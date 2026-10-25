# Plan: trusted-core-policy-v1
Spec: specs/trusted-core-policy-v1.md
Architect verdict: PASS

## Tasks (atomic — each independently shippable)
- [ ] T1 | slice=factoryline | files=factoryline/primitive_observation_binding.py,factoryline/audit_action_refs.py,tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k trusted_core_policy316 -q` | Regenerate and bind an opt-in central policy decision after native tier admission; preserve legacy output and reject forged or stale inputs.
- [ ] T2 | slice=factoryline | files=factoryline/review_audits.py,factoryline/cli_audit.py,tests/test_cli_bootstrap.py | verify=`python -m pytest tests/test_cli_bootstrap.py -k trusted_core_policy316 -q` | Capture current bounded sources for the selected policy and wire matching CLI, JSON, receipt and exit semantics; reject unsupported scopes.

## Evidence boundary
This is a policy and user-interpretation correction, not an accuracy gain. Keep the original actionable precision goal unmet until measured. Future fresh-cohort registration must explicitly name its primary policy and also report legacy raw/active rates, abstentions and true-positive retention.

ECC architecture review: `.factory/precision315/ecc-policy-plan.md`. Approval covers bounded native source regeneration, not implementation correctness or accuracy. Full-repository profiles explicitly reject this policy until their checkpoint integration is separately qualified.
