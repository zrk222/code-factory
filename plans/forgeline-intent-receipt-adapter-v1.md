# Plan: forgeline-intent-receipt-adapter-v1

Spec: specs/forgeline-intent-receipt-adapter-v1.md (must be approved first)
Architect verdict: PASS

## Logical decomposition

1. Capture explicit Forge ship evidence in the standard Factoryline receipt.
2. Prefer the explicit adapter in Graph Ops without weakening legacy fail-closed behavior.
3. Exercise positive, missing-field, and malformed-source paths.
4. Bind the adapter to a sealed intent envelope and non-hollow smoke checks.

## Tasks (atomic — each independently shippable)

- [ ] T1 | slice=factoryline | files=factoryline/assembly.py | verify=`py -3.11 -m pytest -q tests/test_assembly.py -k intent_trace` | Add the read-only Forge output adapter and preserve its hash-bound fields.
- [ ] T2 | slice=factoryline | files=factoryline/graph_ops.py | verify=`py -3.11 -m pytest -q tests/test_graph_ops.py -k intent_trace` | Prefer valid or malformed adapter evidence over legacy Forge projections.
- [ ] T3 | slice=tests | files=tests/test_assembly.py,tests/test_graph_ops.py | verify=`py -3.11 -m pytest -q tests/test_assembly.py tests/test_graph_ops.py` | Cover explicit capture, missing CLI evidence, duplicate suppression, and malformed adapters.
- [ ] T4 | slice=docs | files=docs/EXTERNAL_RUNTIME_EVIDENCE.md | verify=`python -c "from pathlib import Path; assert 'outputs.intent_trace' in Path('docs/EXTERNAL_RUNTIME_EVIDENCE.md').read_text(encoding='utf-8')"` | Document the adapter evidence and external Forge limitation.
- [ ] T5 | slice=forgeline-intent-receipt-adapter-v1 | files=forgeline-intent-receipt-adapter-v1.ssat.yaml | verify=`python -c "from pathlib import Path; assert Path('forgeline-intent-receipt-adapter-v1.ssat.yaml').is_file()"` | Bind implementation markers to the sealed intent.
- [ ] T6 | slice=smoke | files=smoke/forgeline-intent-receipt-adapter-v1.json | verify=`python -c "from pathlib import Path; assert Path('smoke/forgeline-intent-receipt-adapter-v1.json').is_file()"` | Register a non-hollow adapter contract smoke check.
- [ ] T7 | slice=envelopes | files=envelopes/forgeline-intent-receipt-adapter-v1.json | verify=`python -c "from pathlib import Path; assert Path('envelopes/forgeline-intent-receipt-adapter-v1.json').is_file()"` | Seal the intent envelope after the spec gate.

## Non-goals

- No edits to the installed ForgeLine package, upstream `.forge` receipt
  history, provider calls, source-log retrieval, workspace mutation, repair,
  approval, merge, publication, deployment, signing, credential access, or
  connector grant.
