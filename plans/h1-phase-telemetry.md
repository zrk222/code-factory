# Plan: h1-phase-telemetry
Spec: specs/h1-phase-telemetry.md (approved)
Architect verdict: PASS | CONCERNS | FAIL

## Logical decomposition (phases)
1. Add one invocation-local, bounded collector in existing lifecycle telemetry; connect entrypoint and dispatch phases.
2. Measure existing inventory/analysis, proof evaluation and child execution boundaries without new reads or changed verification.
3. Add focused parity, no-source, incomplete/error, privacy, serialization-failure and paired-overhead tests.

## Tasks (atomic — each independently shippable)
- [x] T1 | slice=factoryline | files=factoryline/ops_telemetry.py,factoryline/provenance.py,tests/test_ops_telemetry.py | verify=`python -m pytest tests/test_ops_telemetry.py -q` | add one bounded invocation-local collector and capture entrypoint startup through lifecycle receipt preparation.
- [x] T2 | slice=factoryline | files=factoryline/cli.py,factoryline/ops_telemetry.py,tests/test_cli_bootstrap.py,tests/test_ops_telemetry.py | verify=`python -m pytest tests/test_cli_bootstrap.py tests/test_ops_telemetry.py -q` | capture parser and route phases and include entrypoint time in lifecycle elapsed while preserving CLI outputs and exit codes.
- [x] T3 | slice=factoryline | files=factoryline/adoption.py,factoryline/proof_reuse.py,tests/test_adoption.py,tests/test_proof_reuse.py | verify=`python -m pytest tests/test_adoption.py tests/test_proof_reuse.py -q` | capture existing inventory/audit and proof-evaluation boundaries without additional source/proof reads.
- [x] T4 | slice=factoryline | files=factoryline/assembly_process.py,tests/test_assembly_process.py | verify=`python -m pytest tests/test_assembly_process.py -q` | capture child launch/wait/cleanup and exercise paired enabled/disabled semantic parity plus external receipt-write overhead measurement; run final scoped workflow and CF gates.
