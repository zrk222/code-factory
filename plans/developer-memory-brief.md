# Plan: developer-memory-brief
Spec: specs/developer-memory-brief.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Compose existing Change Review, Continuity, and local Git attribution
   projections into one deterministic, redacted, read-only brief.
2. Expose the brief through local Studio and the stdio MCP boundary.
3. Render source-linked actions without adding execution authority.

## Tasks (atomic — each independently shippable)
- [x] T1 | slice=factoryline/developer_memory.py | files=<=2 | verify=`pytest -q tests/test_developer_memory.py` | Implement bounded brief composition, local Git attribution, and redaction tests.
- [x] T2 | slice=factoryline/mcp.py | files=<=2 | verify=`pytest -q tests/test_mcp.py` | Add read-only MCP tool with explicit changed paths.
- [x] T3 | slice=factoryline/studio.py,factoryline/graph_ops.html | files=<=3 | verify=`pytest -q tests/test_studio.py tests/test_graph_ops.py` | Expose a cached visual Studio/Graph Ops projection with explanatory proof-flow and observed team attribution.
- [x] T4 | slice=factoryline/cli.py | files=<=2 | verify=`pytest -q tests/test_developer_memory.py` | Add a local machine-readable CLI surface.
