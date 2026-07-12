# Plan: privacy-plane-foundation

Spec: specs/privacy-plane.md

- [x] T1 | slice=factoryline | files=factoryline/privacy.py | verify=`python -m pytest -q tests/test_privacy.py` | Implement Merkle selective disclosure and import-guarded BBS/zkVM status
- [x] T2 | slice=tests | files=tests/test_privacy.py | verify=`python -m pytest -q tests/test_privacy.py` | Prove inclusion, mutation rejection, and fail-closed optional backends
- [x] T3 | slice=docs | files=docs/PRIVACY.md | verify=`python -m pytest -q` | Document disclosure and cryptographic scope

