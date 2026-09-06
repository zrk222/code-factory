# Plan: Post-publication runtime hardening

Spec: specs/post-publication-runtime-hardening.md
Architect verdict: PASS

- [x] T1 | slice=factoryline | files=factoryline/proof_reuse.py,factoryline/graph_ops.py,tests/test_proof_reuse.py,tests/test_continuous_proof.py | verify=`python -m pytest -q tests/test_proof_reuse.py tests/test_graph_ops.py tests/test_continuous_proof.py` | Add stable file-identity and replacement-race rejection to proof reuse, preserving superseding proof lineage in Graph Ops.
- [x] T2 | slice=factoryline | files=factoryline/assembly_process.py,tests/test_assembly_process.py | verify=`python -m pytest -q tests/test_assembly_process.py` | Bind child processes to an observable cleanup unit and fail closed on escaped descendants.
- [x] T3a | slice=factoryline | files=factoryline/assembly_process.py,tests/test_assembly_process.py | verify=`python -m pytest -q tests/test_assembly_process.py` | Track observed POSIX descendants by native PID lineage and fail closed when one leaves the invocation process group.
- [x] T3b | slice=.github | files=.github/workflows,tests/test_ci_platform_parity.py | verify=`python -m pytest -q tests/test_ci_platform_parity.py` verifies the Windows-safe scaffold locally; the uploaded Linux/macOS JUnit receipts must prove timeout, output-limit, cancellation, and surviving-child decisions before this box may be checked | Add native Linux and macOS parity receipts without changing the Windows contract.
- [x] T4 | slice=factoryline | files=factoryline/studio.py,tests/test_studio.py | verify=`python -m pytest -q tests/test_studio.py` | Decompose Studio routing under behavior goldens and complexity 10.
