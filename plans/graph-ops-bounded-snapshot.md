# Plan: Graph Ops bounded snapshot
Spec: specs/graph-ops-bounded-snapshot.md
Architect verdict: PASS
- [x] T1 | slice=factoryline | files=factoryline/graph_ops.py | verify=`python -m pytest -q tests/test_graph_ops.py` | Separate collection, facts and marker decisions from the public coordinator.
