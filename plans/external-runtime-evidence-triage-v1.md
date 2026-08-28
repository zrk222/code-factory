# Plan: external-runtime-evidence-triage-v1

Spec: specs/external-runtime-evidence-triage-v1.md (must be approved first)
Architect verdict: PASS

## Logical decomposition

1. Derive one deterministic advisory action from valid failed, blocked, or
   unknown external observations.
2. Preserve invalid/stale refresh precedence and the read-only authority map.
3. Add regression coverage, a bounded architecture contract, and a smoke gate.
4. Document the next-step semantics for developers and reviewers.

## Tasks (atomic — each independently shippable)

- [ ] T1 | slice=factoryline | files=factoryline/graph_ops.py,tests/test_graph_ops.py | verify=`pytest -q tests/test_graph_ops.py -k external` | Derive the read-only external failure triage action and marker while keeping stale evidence on the refresh path.
- [ ] T2 | slice=spec | files=specs/graph-ops-visual-v1.md,specs/external-runtime-evidence-triage-v1.md | verify=`specline strict external-runtime-evidence-triage-v1 --root .` | Align the Graph Ops recommendation vocabulary and seal the triage contract.
- [ ] T3 | slice=external-runtime-evidence-triage-v1.ssat.yaml | files=external-runtime-evidence-triage-v1.ssat.yaml | verify=`python -c "from pathlib import Path; assert Path('external-runtime-evidence-triage-v1.ssat.yaml').is_file()"` | Bind the no-network, no-authority implementation surface.
- [ ] T4 | slice=smoke | files=smoke/external-runtime-evidence-triage-v1.json | verify=`python -c "from pathlib import Path; assert Path('smoke/external-runtime-evidence-triage-v1.json').is_file()"` | Register a non-hollow triage smoke gate.
- [ ] T5 | slice=docs | files=docs/EXTERNAL_RUNTIME_EVIDENCE.md | verify=`rg -n "review_external_runtime_failure" docs/EXTERNAL_RUNTIME_EVIDENCE.md` | Explain how the observation becomes a local review prompt without granting authority.
