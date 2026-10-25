# Plan: pickle-reconstruction-v2
Spec: specs/pickle-reconstruction-v2.md
Architect verdict: PASS

## Tasks (atomic — each independently shippable)
- [ ] T1 | slice=factoryline | files=factoryline/finite_capture.py,tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k pickle_reconstruction317 -q` | Validate canonical versioned contract sets and model initialized Exception reconstruction without repeating historical headers.
- [ ] T2 | slice=factoryline | files=factoryline/runtime_audit_integrity.py,factoryline/primitive_observation_binding.py,tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k pickle_reconstruction317 -q` | Bind cached class lookup and byte dominance, reject mutations/hooks, and independently regenerate selected-contract admission.
- [ ] T3 | slice=factoryline | files=tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k pickle_reconstruction317 -q` | Qualify actual candidates and all pinned controls, then freeze and measure complete matched family outcomes.

## Evidence boundary
Latest completed pickle replay: 2 TP / 32 FP / 2 unclear; H280-021 is the only removed FP. Neither model fixtures nor a policy change count as new detection or precision. All unsupported cases stay active with exact reasons; no claim that 32 cases are resolved before measurement.

ECC architecture approval: `.factory/precision317/ecc-v2-architecture.md`. This approves the bounded design, not implementation or measured removals.
