# Plan: pickle-reconstruction-v4
Spec: specs/pickle-reconstruction-v4.md
Architect verdict: PASS

## Tasks (atomic — each independently shippable)
- [ ] T1 | slice=factoryline | files=factoryline/finite_capture.py,tests/test_context_efficiency.py | verify=`python -m pytest tests/test_context_efficiency.py -k pickle -q` | Implement one bounded graph with identity, source-object/container recipes and protocol-specific reconstruction.
- [ ] T2 | slice=factoryline | files=factoryline/runtime_audit_integrity.py,factoryline/primitive_observation_binding.py,tests/test_finite_capture_origins.py | verify=`python -m pytest tests/test_finite_capture_origins.py -k pickle -q` | Bind generic source/driver facts through independent native admission while preserving raw diagnostics and previous model behavior.
- [ ] T3 | slice=factoryline | files=tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k pickle -q` | Verify backend/state/identity counterexamples and freeze one matched complete37 replay.

## Evidence boundary
Latest completed matched replay: 2 TP, 30 FP and 2 unclear, exposed precision 6.25%. Shared imported-symbol dump/load observations cover30 FP but authorize zero removals. The remaining family and fresh publication target remain incomplete. Source-only artifacts and controlled runtime conformance are not target deployment evidence.
