# Plan: pickle-reconstruction-v3
Spec: specs/pickle-reconstruction-v3.md
Architect verdict: PASS

## Tasks (atomic — each independently shippable)
- [ ] T1 | slice=factoryline | files=factoryline/runtime_audit_integrity.py,tests/test_finite_capture_origins.py | verify=`python -m pytest tests/test_finite_capture_origins.py -k pickle -q` | Bind local byte origins without granting reconstruction authority or altering old model decisions.
- [ ] T2 | slice=factoryline | files=factoryline/finite_capture.py,tests/test_context_efficiency.py | verify=`python -m pytest tests/test_context_efficiency.py -k pickle -q` | Add a versioned, source-bound typed enum reconstruction model and reject unknown graph effects.
- [ ] T3 | slice=factoryline | files=factoryline/runtime_audit_integrity.py,factoryline/primitive_observation_binding.py | verify=`python .factory/precision324/verify_measurement.py` | Integrate native independent admission and measure all 37 original claims on frozen matched contexts.

## Evidence boundary
The complete family is unresolved: current measured active outcomes are 2 TP, 31 FP and 2 unclear. A typed enum recipe is a reusable implementation increment, not a promise to resolve all remaining driver, helper, reducer and IPC cases. Keep the full objective active and publish no fresh-held-out number from this exposed replay.
