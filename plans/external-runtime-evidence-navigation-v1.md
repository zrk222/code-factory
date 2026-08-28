# Plan: external-runtime-evidence-navigation-v1

Spec: specs/external-runtime-evidence-navigation-v1.md (must be approved first)
Architect verdict: PASS

## Logical decomposition

1. Give rendered Graph Ops nodes stable local identifiers.
2. Add the evidence-card navigation affordance with a missing-target guard.
3. Preserve read-only authority and narrow-screen usability.
4. Bind the implementation to a sealed intent envelope and verify the UI.

## Tasks (atomic — each independently shippable)

- [ ] T1 | slice=factoryline | files=factoryline/graph_ops.html | verify=`pytest -q tests/test_graph_ops.py -k visual` | Render the local-only node locator, stable node identifiers, and responsive control.
- [ ] T2 | slice=tests | files=tests/test_graph_ops.py | verify=`pytest -q tests/test_graph_ops.py -k visual` | Assert navigation markers, missing-target copy, text-node rendering, and scroll behavior.
- [ ] T3 | slice=docs | files=docs/EXTERNAL_RUNTIME_EVIDENCE.md | verify=`python -c "from pathlib import Path; assert 'Inspect node details' in Path('docs/EXTERNAL_RUNTIME_EVIDENCE.md').read_text()"` | Document the evidence-locator boundary and no-authority behavior.
- [ ] T4 | slice=external-runtime-evidence-navigation-v1 | files=external-runtime-evidence-navigation-v1.ssat.yaml | verify=`python -c "from pathlib import Path; assert Path('external-runtime-evidence-navigation-v1.ssat.yaml').is_file() and Path('envelopes/external-runtime-evidence-navigation-v1.json').is_file()"` | Bind the four requirements to the sealed intent and non-hollow smoke checks.

## Non-goals

- No external provider calls, source-log retrieval, workspace mutation, repair,
  approval, merge, publication, deployment, credential access, or connector
  grant.
