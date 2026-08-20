# Plan: earned-autonomy-v1

Spec: `specs/earned-autonomy-v1.md`
Architect verdict: PASS — bounded local governance with explicit identity and
signature limits.

## Logical decomposition

1. Specify immutable governed-run events and deterministic license derivation.
2. Enforce licenses at admission time without changing undeclared legacy runs.
3. Seal and score proof-bound multi-agent task comparisons without executing
   agent commands.
4. Expose read-only Graph Ops and MCP projections, tests, docs, and packaging.

## Tasks

- [ ] T1 | slice=factoryline/agent_license.py,tests/test_agent_license.py | files=<=2 | verify=`python -m pytest -q tests/test_agent_license.py` | Implement canonical event ledger, decay, severe demotion, incident capsules, offline verification, and optional DSSE sealing.
- [ ] T2 | slice=factoryline/run_admission.py,tests/test_run_admission.py | files=<=2 | verify=`python -m pytest -q tests/test_run_admission.py tests/test_agent_license.py` | Add declared identity parsing and fail-closed license caps at admission.
- [ ] T3 | slice=factoryline/combine.py,tests/test_combine.py | files=<=2 | verify=`python -m pytest -q tests/test_combine.py tests/test_agent_license.py` | Implement sealed tasks and canonical evidence scoreboards with no agent command execution.
- [ ] T4 | slice=factoryline/cli.py,factoryline/mcp.py,factoryline/graph_ops.py,tests/test_mcp.py | files=<=4 | verify=`python -m pytest -q tests/test_mcp.py tests/test_graph_ops.py` | Expose guarded CLI and read-only local projections.
- [ ] T5 | slice=docs,specs,README.md,tests | files=<=4 | verify=`python -m pytest -q tests/test_agent_license.py tests/test_combine.py tests/test_publication_metadata.py` | Document exact capability limits and validate release-facing language.
