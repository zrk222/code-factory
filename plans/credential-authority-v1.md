# Plan: credential-authority-v1
Spec: specs/credential-authority-v1.md
Architect verdict: NEEDS_WORK

## Tasks (atomic — each independently shippable)
- [ ] T1 | slice=factoryline | files=factoryline/semantic_credential_sensor.py,tests/test_semantic_credential_sensor.py | verify=`python -m pytest tests/test_semantic_credential_sensor.py -k credential_authority315 -q` | Bind declaration, configured app, request comparison and session authority using existing native predicates; reject unsupported provider or mutation evidence.
- [ ] T2 | slice=factoryline | files=factoryline/primitive_observation_binding.py,tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k credential_authority315 -q` | Independently admit the source-bound positive witness on the original diagnostic identity and measure retention separately from precision.

## Evidence boundary
The latest complete exposed replay remains 6 TP / 75 FP / 11 unclear. Positive support of an existing TP does not increase that numerator. This feature is complete only with independently regenerated public-path evidence; unavailable provider or export facts remain incomplete.

## Feasibility stop
ECC review `.factory/precision315/ecc-authority-plan.md` found unresolved wildcard/provider effects, application escape into FlaskDB and session-signing assumptions. Root inspected the captured FlaskDB class: it stores the application and registers callbacks. No implementation is admitted by this packet. Do not replace these missing premises with package names or generic fixture passes. Resume only with a source-backed effect/export contract that closes an actual candidate.
