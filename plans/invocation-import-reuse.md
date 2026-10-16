# Plan: invocation-import-reuse
Spec: specs/invocation-import-reuse.md (approved before implementation)
Architect verdict: PASS

## Tasks (atomic — each independently shippable)
- [ ] T1 | slice=factoryline | files=factoryline/review_audits.py,factoryline/implementation_audit.py,factoryline/intent_quality.py | verify=`ruff check factoryline/review_audits.py factoryline/implementation_audit.py` | Capture bounded immutable import views and reuse only matching inventories with full fallback.
- [ ] T2 | slice=tests | files=tests/test_review_integrity.py | verify=`python -m pytest -q tests/test_review_integrity.py -k invocation_import` | Prove reuse, immutable views, inventory mismatch, bounds, source drift and cold/warm/changed parity.

