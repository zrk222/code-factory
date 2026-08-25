# Plan: forgeline-intent-receipt-integrity-v1

Spec: specs/forgeline-intent-receipt-integrity-v1.md (must be approved first)
Architect verdict: PASS

## Logical decomposition

1. Verify the adapter's claimed Forge-line binding against the current bounded source.
2. Preserve fail-closed status and expose exact provenance facts.
3. Explain mismatch and unbound states in the existing read-only Graph Ops panel.
4. Bind the slice to mutation-tested spec and smoke evidence.

## Tasks (atomic — each independently shippable)

- [ ] T1 | slice=factoryline | files=factoryline/graph_ops.py | verify=`py -3.11 -m pytest -q tests/test_graph_ops.py -k binding` | Compare adapter hash and explicit values with the exact Forge ship line.
- [ ] T2 | slice=factoryline | files=factoryline/graph_ops.py | verify=`py -3.11 -m pytest -q tests/test_graph_ops.py -k intent_trace` | Preserve untraceable status and mismatch/unbound facts without fallback.
- [ ] T3 | slice=tests | files=tests/test_graph_ops.py | verify=`py -3.11 -m pytest -q tests/test_graph_ops.py -k adapter` | Cover bound, mismatch, malformed, and missing provenance sources.
- [ ] T4 | slice=factoryline | files=factoryline/graph_ops.html | verify=`python -c "from pathlib import Path; assert 'GRAPH_OPS_INTENT_ADAPTER_MISMATCH' in Path('factoryline/graph_ops.html').read_text(encoding='utf-8')"` | Render provenance facts and review-required mismatch copy.
- [ ] T5 | slice=docs | files=docs/EXTERNAL_RUNTIME_EVIDENCE.md | verify=`python -c "from pathlib import Path; assert 'GRAPH_OPS_INTENT_ADAPTER_MISMATCH' in Path('docs/EXTERNAL_RUNTIME_EVIDENCE.md').read_text(encoding='utf-8')"` | Document the exact binding check and boundary.
- [ ] T6 | slice=forgeline-intent-receipt-integrity-v1 | files=forgeline-intent-receipt-integrity-v1.ssat.yaml | verify=`python -c "from pathlib import Path; assert Path('forgeline-intent-receipt-integrity-v1.ssat.yaml').is_file()"` | Bind source markers to the sealed intent.
- [ ] T7 | slice=smoke | files=smoke/forgeline-intent-receipt-integrity-v1.json | verify=`python -c "from pathlib import Path; assert Path('smoke/forgeline-intent-receipt-integrity-v1.json').is_file()"` | Register the non-hollow provenance smoke check.
- [ ] T8 | slice=envelopes | files=envelopes/forgeline-intent-receipt-integrity-v1.json | verify=`python -c "from pathlib import Path; assert Path('envelopes/forgeline-intent-receipt-integrity-v1.json').is_file()"` | Seal the intent envelope after the spec gate.

## Non-goals

- No provider calls, workspace mutation, automatic repair, execution,
  approval, merge, publication, deployment, signing, credential access, or
  connector grant.
