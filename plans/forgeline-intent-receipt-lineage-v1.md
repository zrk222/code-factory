# Plan: forgeline-intent-receipt-lineage-v1

Spec: specs/forgeline-intent-receipt-lineage-v1.md (must be approved first)
Architect verdict: PASS

## Logical decomposition

1. Return the exact bounded Forge source and line with the existing hash binding.
2. Preserve fail-closed null lineage for missing, malformed, or mismatched evidence.
3. Expose the location in the read-only Graph Ops intent panel.
4. Add deterministic tests and sealed smoke/spec evidence.

## Tasks (atomic — each independently shippable)

- [ ] T1 | slice=factoryline | files=factoryline/graph_ops.py | verify=`py -3.11 -m pytest -q tests/test_graph_ops.py -k lineage` | Return normalized Forge source and exact 1-based ship-line number.
- [ ] T2 | slice=factoryline | files=factoryline/graph_ops.py | verify=`py -3.11 -m pytest -q tests/test_graph_ops.py -k adapter` | Keep lineage null and traceability fail-closed when binding cannot be established.
- [ ] T3 | slice=tests | files=tests/test_graph_ops.py | verify=`py -3.11 -m pytest -q tests/test_graph_ops.py -k lineage` | Cover bound, missing, and malformed lineage sources.
- [ ] T4 | slice=factoryline | files=factoryline/graph_ops.html | verify=`python -c "from pathlib import Path; assert 'Forge source' in Path('factoryline/graph_ops.html').read_text(encoding='utf-8')"` | Render the source and line as read-only facts.
- [ ] T5 | slice=docs | files=docs/EXTERNAL_RUNTIME_EVIDENCE.md | verify=`python -c "from pathlib import Path; assert 'lineage' in Path('docs/EXTERNAL_RUNTIME_EVIDENCE.md').read_text(encoding='utf-8').lower()"` | Document offline reviewer navigation and authority limits.
- [ ] T6 | slice=forgeline-intent-receipt-lineage-v1 | files=forgeline-intent-receipt-lineage-v1.ssat.yaml | verify=`python -c "from pathlib import Path; assert Path('forgeline-intent-receipt-lineage-v1.ssat.yaml').is_file()"` | Bind source markers to the sealed intent.
- [ ] T7 | slice=smoke | files=smoke/forgeline-intent-receipt-lineage-v1.json | verify=`python -c "from pathlib import Path; assert Path('smoke/forgeline-intent-receipt-lineage-v1.json').is_file()"` | Register the non-hollow lineage smoke check.
- [ ] T8 | slice=envelopes | files=envelopes/forgeline-intent-receipt-lineage-v1.json | verify=`python -c "from pathlib import Path; assert Path('envelopes/forgeline-intent-receipt-lineage-v1.json').is_file()"` | Seal the intent envelope after the spec gate.

## Non-goals

- No provider calls, workspace mutation, automatic repair, execution, approval, merge, publication, deployment, signing, credential access, or connector grant.
