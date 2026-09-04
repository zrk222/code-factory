# Plan: Post-publication runtime hardening

Spec: specs/post-publication-runtime-hardening.md
Architect verdict: PASS

- [ ] T1 | slice=factoryline | files=factoryline/proof_reuse.py,tests/test_proof_reuse.py | verify=`python -m pytest -q tests/test_proof_reuse.py` | Add stable file-identity and replacement-race rejection to proof reuse.
- [ ] T2 | slice=factoryline | files=factoryline/assembly_process.py,tests/test_assembly_process.py | verify=`python -m pytest -q tests/test_assembly_process.py` | Bind child processes to an observable cleanup unit and fail closed on escaped descendants.
- [ ] T3 | slice=.github | files=.github/workflows,tests/test_ci_platform_parity.py | verify=`python -m pytest -q tests/test_ci_platform_parity.py` verifies only the native-runner/Python matrix scaffold; the four native fixture decisions remain required before this box may be checked | Add native Linux and macOS parity receipts without changing the Windows contract.
- [ ] T4 | slice=factoryline | files=factoryline/studio.py,tests/test_studio.py | verify=`python -m pytest -q tests/test_studio.py` | Decompose Studio routing under behavior goldens and complexity 10.
