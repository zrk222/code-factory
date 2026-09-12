# Plan: intake-parameters-v1

Spec: specs/intake-parameters-v1.md
Architect verdict: PASS

- [x] T1 | slice=specs | files=specs/intake-parameters-v1.md,specs/intake-parameters-v1.ssat.yaml | verify=`specline strict intake-parameters-v1 --root .` | Define exact envelope fields, origins, bounds, expiry, and authority.
- [x] T2 | slice=factoryline | files=factoryline/intake_parameters.py | verify=`py -3.11 -m pytest -q tests/test_intake_parameters.py` | Seal and verify source-bound, fail-closed parameters with drift and advisory provenance handling.
- [x] T3 | slice=factoryline | files=factoryline/mission_control_status.py,factoryline/graph_ops.py | verify=`py -3.11 -m pytest -q tests/test_graph_ops.py` | Expose blocked/review-required intake state and one next action without altering the timing baseline.
- [x] T4 | slice=factoryline | files=factoryline/cli.py,factoryline/mcp.py,factoryline/webmcp.py,factoryline/junie_taxonomy.py | verify=`py -3.11 -m pytest -q tests/test_mcp.py tests/test_webmcp.py tests/test_junie_taxonomy.py` | Add discoverable CLI and read-only agent interfaces.
- [x] T5 | slice=docs | files=docs/INTAKE_PARAMETERS.md | verify=`git diff --check` | Document the novice path, proof boundary, and recovery action.

## Explicit non-goals

- No automatic promotion of agent-proposed values.
- No provider, credential, network, execution, release, or deployment action.
