# Plan: pickle-context-role-v1
Spec: specs/pickle-context-role-v1.md
Architect verdict: PASS

## Tasks (atomic — each independently shippable)
- [ ] T1 | slice=factoryline | files=factoryline/primitive_observation_binding.py,factoryline/audit_action_refs.py | verify=`python -m pytest tests/test_finite_capture_origins.py -k pickle_role -q` | Rebuild positive test-role/import/provenance facts, retain dangerous effects, and emit a separate needs-context collection under an explicit policy.
- [ ] T2 | slice=factoryline | files=factoryline/review_audits.py,factoryline/cli_audit.py,tests/test_finite_capture_origins.py | verify=`python -m pytest tests/test_finite_capture_origins.py -k pickle_role -q` | Expose the versioned selector, original diagnostics, exclusions, review counts and non-clean claim boundary.
- [ ] T3 | slice=factoryline | files=tests/test_finite_capture_origins.py | verify=`python .factory/precision326/verify_role_measurement.py` | Freeze one matched full37 replay and publish both unchanged legacy and policy-selected metrics with retention and sample-size limits.

## Architecture scope
Follow the supplied owner report's explicit NEEDS_CONTEXT output policy; this packet does not grant negative reconstruction authority. Raw severity and the legacy route remain unchanged. The role decision requires a complete captured inventory, direct collected test scope, positive framework evidence and importer/callback counterevidence checks. The independent role-policy review is required before a completion or release claim.
