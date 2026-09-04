# Plan: Oracle audit parity
Spec: specs/oracle-audit-parity.md
Architect verdict: PASS
- [x] T1 | slice=factoryline | files=factoryline/oracle_firewall.py | verify=`python -m pytest -q tests/test_oracle_firewall.py` | Restore constructor/verifier rule parity and original-intent binding.
- [x] T2 | slice=factoryline | files=factoryline/appforge_submission_integrity.py | verify=`python -m pytest -q tests/test_appforge_submission_integrity.py` | Revalidate original capture requirements before file reconciliation.

Implementation tests pass. Broad architecture/drift review remains blocked as recorded in docs/MODULE_AUDIT_REGISTER.md; this is not release clearance.
