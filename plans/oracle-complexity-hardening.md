# Plan: Oracle complexity hardening

Spec: specs/oracle-complexity-hardening.md
Architect verdict: PASS

- [x] T1 | slice=factoryline | files=factoryline/codex_metadata.py,tests/test_codex_metadata.py | verify=`python -m pytest -q tests/test_codex_metadata.py` | Bound post-read bytes, reject explicit empty selection and reduce the metadata coordinator.
- [x] T2 | slice=factoryline | files=factoryline/oracle_firewall.py,tests/test_oracle_firewall.py | verify=`python -m pytest -q tests/test_oracle_firewall.py` | Reconstruct challenge cases and incident drift, reject malformed result rows and reduce all five Oracle coordinators.
- [x] T3 | slice=docs | files=docs/MODULE_AUDIT_REGISTER.md | verify=`forge qa oracle-audit-parity --ssat specs/oracle-firewall-v1.ssat.yaml --strict` | Reconcile the register with scoped and full-suite receipts.
