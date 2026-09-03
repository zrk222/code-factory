# Plan: atomic-proof-adapter-v1
Spec: specs/atomic-proof-adapter-v1.md (must be approved first)
Architect verdict: PASS

## Logical decomposition (phases)
1. Define the strict hash-only Atomic envelope and adapter receipt: a typed
   stage DAG, scope/capability-bound handoffs, checkpoint continuity, artifact
   lifecycle, and immutable source preconditions bound to a current Oracle
   Contract without an Atomic runtime dependency.
2. Add a CLI import/status surface, Graph Ops projection, and read-only MCP /
   WebMCP status. The UI is a projection, never an execution control.
3. Prove normal import, scope escape, topology rejection, resume divergence,
   privacy rejection, Graph Ops, MCP/WebMCP, and package integrity.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [x] T1 | slice=factoryline | files=factoryline/atomic_proof_adapter.py,tests/test_atomic_proof_adapter.py | verify=`py -3.11 -m pytest -q tests/test_atomic_proof_adapter.py` | Implement typed DAG, scoped intercom handoffs, checkpoint continuity, artifact preconditions, strict import, projection, and focused tests.
- [x] T2 | slice=factoryline | files=factoryline/cli.py,factoryline/graph_ops.py,factoryline/mcp.py,factoryline/webmcp.py | verify=`py -3.11 -m pytest -q tests/test_atomic_proof_adapter.py tests/test_graph_ops.py tests/test_mcp.py tests/test_webmcp.py` | Add bounded CLI, Graph Ops, MCP, and WebMCP status projections.
- [x] T3 | slice=specs | files=specs/atomic-proof-adapter-v1.ssat.yaml | verify=`py -3.11 -m specline.cli strict atomic-proof-adapter-v1 --root .` | Add the executable adapter contract.
- [x] T4 | slice=docs | files=docs/ATOMIC_PROOF_ADAPTER.md | verify=`py -3.11 -m pytest -q tests/test_atomic_proof_adapter.py` | Add exact user guidance and authority boundaries.
- [x] T5 | slice=README.md | files=README.md | verify=`py -3.11 -m pytest -q tests/test_atomic_proof_adapter.py` | Add concise discovery copy without unsupported claims.
