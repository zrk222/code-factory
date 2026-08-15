# Plan: graph-forensics-v1
Spec: specs/graph-forensics-v1.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Define and verify the bounded lineage contract.
2. Compare verified runs and calculate anomaly and recovery facts.
3. Expose CLI, Graph Ops, Studio, and operator documentation.
4. Prove rejection behavior and repository compatibility.

## Tasks (atomic - each independently shippable)
- [ ] T1 | slice=factoryline | files=factoryline/graph_forensics.py | verify=`python -m pytest -q tests/test_graph_forensics.py` | Implement lineage sealing, verification, and deterministic forensic analysis.
- [ ] T2 | slice=factoryline | files=factoryline/cli.py,factoryline/graph_ops.py,factoryline/graph_ops.html | verify=`python -m pytest -q tests/test_graph_forensics.py tests/test_graph_ops.py` | Add CLI commands and Graph Ops lineage and forensics lanes.
- [ ] T3 | slice=docs | files=docs/GRAPH_FORENSICS.md,docs/GRAPH_OPS.md,docs/OVERVIEW.md | verify=`python -m pytest -q tests/test_graph_forensics.py` | Document the operator contract, scope limits, commands, and public overview.
- [ ] T4 | slice=tests | files=tests/test_graph_forensics.py,tests/test_graph_ops.py | verify=`python -m pytest -q tests/test_graph_forensics.py tests/test_graph_ops.py tests/test_mission_graph.py` | Prove tamper, divergence, anomaly, reducer, mission-ledger, and read-only behavior.
