# Plan: captured-program-origin-v1
Spec: specs/captured-program-origin-v1.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Check interpretation-time effects without executing target code.
2. Trace a dynamic program through path, file-handle, read, assignment and compile edges.
3. Combine both proofs in the native producer and independently regenerate the decision.
4. Qualify all candidates and adversarial controls, then measure the complete matched exposed panel.

## Tasks (atomic — each independently shippable)
- [ ] T1 | slice=factoryline | files=factoryline/finite_capture.py,tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k captured_program -q` | Prove bounded interpretation effects for captured declarative programs and reject effectful headers, calls and namespace writes.
- [ ] T2 | slice=factoryline | files=factoryline/runtime_audit_integrity.py,tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k captured_program -q` | Bind file-backed origins to current caller and program bytes without target I/O.
- [ ] T3 | slice=factoryline | files=factoryline/review_audits.py,factoryline/audit_action_refs.py,factoryline/context_efficiency.py,tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k captured_program -q` | Wire source-bound candidate production and current captured context without changing raw priorities.
- [ ] T4 | slice=factoryline | files=factoryline/primitive_observation_binding.py,tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k captured_program -q` | Independently regenerate native admission, preserve raw records, and qualify complete matched measurements.

## Evidence boundary
Study311 remains 6 TP / 76 FP by default and 6 TP / 75 FP under its conditional reconstruction profile. These are exposed-panel results. The next four file-backed cases are implementation candidates, not promised eliminations. A file origin without accepted effect and namespace evidence stays active.
