# Plan: gauntlet-survival-card-v1
Spec: specs/gauntlet-survival-card-v1.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Compile source-bound promise/sabotage proposals and verify stale or tampered inputs without execution.
2. Add named, expiring one-batch admission and reuse the existing E2E runner for admitted local execution only.
3. Seal outcomes into an integrity-checked public Survival Card, deterministic SVG/Markdown views, optional Receipt v2 DSSE binding, and a mutation check.
4. Project cards read-only into Graph Ops and MCP.
5. Validate CLI, documentation, packaging, full test suite, and release artifacts.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [ ] T1 | slice=factoryline | files=<=4 | verify=`python -m pytest -q tests/test_gauntlet.py -k proposal` | Add source-bound promise/case proposal compilation and stale/tamper tests.
- [ ] T2 | slice=factoryline | files=<=4 | verify=`python -m pytest -q tests/test_gauntlet.py -k admission` | Add named expiry-bound admission and no-admission execution rejection.
- [ ] T3 | slice=factoryline | files=<=4 | verify=`python -m pytest -q tests/test_gauntlet.py -k card` | Add E2E-backed cards, offline verification, SVG, and optional DSSE subject binding.
- [ ] T4 | slice=factoryline | files=<=4 | verify=`python -m pytest -q tests/test_graph_ops.py tests/test_mcp.py tests/test_gauntlet.py` | Add Graph Ops and MCP read-only Gauntlet projection.
- [ ] T5 | slice=. | files=<=4 | verify=`python -m build; python -m twine check dist/*; python -m pytest -q` | Align docs, release metadata, and full artifact evidence.
