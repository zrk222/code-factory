# Plan: external-runtime-evidence-triage-ui-v1

Spec: specs/external-runtime-evidence-triage-ui-v1.md (must be approved first)
Architect verdict: PASS

## Logical decomposition

1. Add a review-first callout to the existing observed-runtime lane.
2. Keep stale/invalid precedence and the no-authority copy explicit.
3. Preserve text-node rendering and narrow-screen layout.
4. Prove the static contract, design quality, and Graph Ops regressions.

## Tasks (atomic — each independently shippable)

- [ ] T1 | slice=factoryline | files=factoryline/graph_ops.html | verify=`pytest -q tests/test_graph_ops.py -k visual` | Render the deterministic triage callout and responsive styles using the existing payload.
- [ ] T2 | slice=tests | files=tests/test_graph_ops.py | verify=`pytest -q tests/test_graph_ops.py -k visual` | Assert the triage panel, markers, authority copy, and text-node boundary.
- [ ] T3 | slice=external-runtime-evidence-triage-ui-v1.ssat.yaml | files=external-runtime-evidence-triage-ui-v1.ssat.yaml | verify=`python -c "from pathlib import Path; assert Path('external-runtime-evidence-triage-ui-v1.ssat.yaml').is_file()"` | Bind the no-network/no-mutation surface.
- [ ] T4 | slice=smoke | files=smoke/external-runtime-evidence-triage-ui-v1.json | verify=`python -c "from pathlib import Path; assert Path('smoke/external-runtime-evidence-triage-ui-v1.json').is_file()"` | Register the non-hollow static UI smoke gate.
