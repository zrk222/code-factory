# Plan: forgeline-intent-lineage-navigation-v1

Spec: specs/forgeline-intent-lineage-navigation-v1.md (must be approved first)
Architect verdict: PASS

## Logical decomposition

1. Render a compact, readable lineage path in each intent card.
2. Reuse existing read-only node focus for source inspection.
3. Keep missing/unbound lineage visibly fail closed.
4. Prove responsive/static safety and record sealed gates.

## Tasks (atomic — each independently shippable)

- [ ] T1 | slice=factoryline | files=factoryline/graph_ops.html | verify=`python -c "from pathlib import Path; page=Path('factoryline/graph_ops.html').read_text(encoding='utf-8'); assert 'Intent trace' in page and 'Inspect source' in page"` | Render the lineage path and read-only source navigation.
- [ ] T2 | slice=factoryline | files=factoryline/graph_ops.html | verify=`python -c "from pathlib import Path; page=Path('factoryline/graph_ops.html').read_text(encoding='utf-8'); assert 'No traversable Forge lineage' in page and 'innerHTML' not in page"` | Withhold navigation when no verified source node exists.
- [ ] T3 | slice=tests | files=tests/test_graph_ops.py | verify=`py -3.11 -m pytest -q tests/test_graph_ops.py -k visual` | Lock markers, text, and focus wiring.
- [ ] T4 | slice=docs | files=docs/EXTERNAL_RUNTIME_EVIDENCE.md | verify=`python -c "from pathlib import Path; text=Path('docs/EXTERNAL_RUNTIME_EVIDENCE.md').read_text(encoding='utf-8'); assert 'Inspect source' in text"` | Document the reviewer navigation boundary.
- [ ] T5 | slice=forgeline-intent-lineage-navigation-v1 | files=forgeline-intent-lineage-navigation-v1.ssat.yaml | verify=`python -c "from pathlib import Path; assert Path('forgeline-intent-lineage-navigation-v1.ssat.yaml').is_file()"` | Bind UI and fail-closed markers to the sealed intent.
- [ ] T6 | slice=smoke | files=smoke/forgeline-intent-lineage-navigation-v1.json | verify=`python -c "from pathlib import Path; assert Path('smoke/forgeline-intent-lineage-navigation-v1.json').is_file()"` | Register the non-hollow navigation smoke check.
- [ ] T7 | slice=envelopes | files=envelopes/forgeline-intent-lineage-navigation-v1.json | verify=`python -c "from pathlib import Path; assert Path('envelopes/forgeline-intent-lineage-navigation-v1.json').is_file()"` | Seal the navigation intent envelope.

## Non-goals

- No provider calls, workspace mutation, automatic repair, execution, approval, merge, publication, deployment, signing, credential access, or connector grant.
