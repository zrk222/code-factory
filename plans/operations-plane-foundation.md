# Plan: operations-plane-foundation

Spec: specs/operations-plane.md

- [x] T1 | slice=factoryline | files=factoryline/operations.py | verify=`python -m pytest -q tests/test_operations.py` | Implement telemetry, canary, rollback, vulnerability, and connector contracts
- [x] T2 | slice=tests | files=tests/test_operations.py | verify=`python -m pytest -q tests/test_operations.py` | Prove measured spans and thresholded decisions
- [x] T3 | slice=docs | files=docs/OPERATIONS.md | verify=`python -m pytest -q` | Document metadata-only and no-network scope

