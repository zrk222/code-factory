# Plan: forgeline-intent-receipt-lineage-edge-v1

Spec: specs/forgeline-intent-receipt-lineage-edge-v1.md (must be approved first)
Architect verdict: PASS

## Logical decomposition

1. Project a stable source node and verified edge only for a fully bound adapter.
2. Preserve fail-closed no-node/no-edge behavior for all untrusted states.
3. Expose both node kinds in the read-only Graph Ops lanes.
4. Add deterministic tests and sealed smoke/spec evidence.

## Tasks (atomic — each independently shippable)

- [ ] T1 | slice=factoryline | files=factoryline/graph_ops.py | verify=`py -3.11 -m pytest -q tests/test_graph_ops.py -k adapter` | Project the verified Forge line as an intent_source node and bound_to_forge_line edge.
- [ ] T2 | slice=factoryline | files=factoryline/graph_ops.py | verify=`py -3.11 -m pytest -q tests/test_graph_ops.py -k adapter` | Keep untrusted adapter states free of lineage nodes and edges.
- [ ] T3 | slice=tests | files=tests/test_graph_ops.py | verify=`py -3.11 -m pytest -q tests/test_graph_ops.py -k adapter` | Cover bound, missing, malformed, and mismatched projections.
- [ ] T4 | slice=factoryline | files=factoryline/graph_ops.html | verify=`python -c "from pathlib import Path; page=Path('factoryline/graph_ops.html').read_text(encoding='utf-8'); assert 'intent_trace' in page and 'intent_source' in page and 'GRAPH_OPS_INTENT_LINEAGE_EDGE_READ_ONLY' in page"` | Render the two node lanes without adding controls.
- [ ] T5 | slice=docs | files=docs/EXTERNAL_RUNTIME_EVIDENCE.md | verify=`python -c "from pathlib import Path; assert 'bound_to_forge_line' in Path('docs/EXTERNAL_RUNTIME_EVIDENCE.md').read_text(encoding='utf-8')"` | Document graph traversal and authority boundaries.
- [ ] T6 | slice=forgeline-intent-receipt-lineage-edge-v1 | files=forgeline-intent-receipt-lineage-edge-v1.ssat.yaml | verify=`python -c "from pathlib import Path; assert Path('forgeline-intent-receipt-lineage-edge-v1.ssat.yaml').is_file()"` | Bind node, edge, fail-closed, and UI markers to the sealed intent.
- [ ] T7 | slice=smoke | files=smoke/forgeline-intent-receipt-lineage-edge-v1.json | verify=`python -c "from pathlib import Path; assert Path('smoke/forgeline-intent-receipt-lineage-edge-v1.json').is_file()"` | Register the non-hollow graph-lineage smoke check.
- [ ] T8 | slice=envelopes | files=envelopes/forgeline-intent-receipt-lineage-edge-v1.json | verify=`python -c "from pathlib import Path; assert Path('envelopes/forgeline-intent-receipt-lineage-edge-v1.json').is_file()"` | Seal the intent envelope after the spec gate.

## Non-goals

- No provider calls, workspace mutation, automatic repair, execution, approval, merge, publication, deployment, signing, credential access, or connector grant.
