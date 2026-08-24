# Plan: intent-trace-graph-ops-v1

Spec: specs/intent-trace-graph-ops-v1.md (must be approved first)
Architect verdict: PASS

## Logical decomposition

1. Project the newest bounded local Forge ship receipt into the Graph Ops snapshot.
2. Render trace facts and fail-closed states in the existing Graph Ops panel.
3. Preserve the no-authority boundary and narrow-screen layout.
4. Bind the implementation to a sealed intent envelope and non-hollow smoke checks.

## Tasks (atomic — each independently shippable)

- [ ] T1 | slice=factoryline | files=factoryline/graph_ops.py,factoryline/graph_ops.html | verify=`py -3.11 -m pytest -q tests/test_graph_ops.py -k visual` | Project local ship receipts and render the read-only intent trace panel.
- [ ] T2 | slice=tests | files=tests/test_graph_ops.py | verify=`py -3.11 -m pytest -q tests/test_graph_ops.py -k graph_ops` | Assert traceable, untraceable, fail-closed, and marker behavior.
- [ ] T3 | slice=docs | files=docs/EXTERNAL_RUNTIME_EVIDENCE.md | verify=`python -c "from pathlib import Path; assert 'Intent trace in Graph Ops' in Path('docs/EXTERNAL_RUNTIME_EVIDENCE.md').read_text(encoding='utf-8')"` | Document receipt projection, provenance, and non-authority boundaries.
- [ ] T4 | slice=intent-trace-graph-ops-v1 | files=intent-trace-graph-ops-v1.ssat.yaml | verify=`python -c "from pathlib import Path; assert Path('intent-trace-graph-ops-v1.ssat.yaml').is_file()"` | Bind requirements to source markers and smoke gates.
- [ ] T5 | slice=smoke | files=smoke/intent-trace-graph-ops-v1.json | verify=`python -c "from pathlib import Path; assert Path('smoke/intent-trace-graph-ops-v1.json').is_file()"` | Register a non-hollow static UI and authority-boundary smoke gate.

## Non-goals

- No external provider calls, Forge execution, receipt repair, workspace
  mutation, authorization, approval, merge, publication, deployment, signing,
  credential access, connector grant, or new Graph Ops endpoint.
