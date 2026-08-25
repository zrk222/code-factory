# Plan: external-runtime-evidence-ui-v1

Spec: specs/external-runtime-evidence-ui-v1.md (must be approved first)
Architect verdict: PASS

## Logical decomposition

1. Add the observed-runtime panel to the existing Graph Ops page.
2. Render normalized external facts and hypotheses without HTML insertion.
3. Preserve the read-only authority boundary and narrow-screen layout.
4. Prove the static UI contract and existing Graph Ops regression suite.

## Tasks (atomic — each independently shippable)

- [ ] T1 | slice=factoryline | files=factoryline/graph_ops.html | verify=`pytest -q tests/test_graph_ops.py -k visual` | Add the responsive observed-runtime lane, fact/hypothesis separation, and read-only authority copy.
- [ ] T2 | slice=tests | files=tests/test_graph_ops.py | verify=`pytest -q tests/test_graph_ops.py -k visual` | Prove the observed-runtime panel contract and text-node boundary.
- [ ] T3 | slice=external-runtime-evidence-ui-v1.ssat.yaml | files=external-runtime-evidence-ui-v1.ssat.yaml | verify=`python -c "from pathlib import Path; assert Path('external-runtime-evidence-ui-v1.ssat.yaml').is_file()"` | Seal the bounded template contract.
- [ ] T4 | slice=smoke | files=smoke/external-runtime-evidence-ui-v1.json | verify=`python -c "from pathlib import Path; assert Path('smoke/external-runtime-evidence-ui-v1.json').is_file()"` | Register the non-hollow UI smoke contract.
- [ ] T5 | slice=docs | files=docs/EXTERNAL_RUNTIME_EVIDENCE.md | verify=`pytest -q tests/test_graph_ops.py -k visual` | Document that imported runtime evidence is visible in Graph Ops but never authority.
