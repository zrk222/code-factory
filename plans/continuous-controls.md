# Plan: continuous-controls
Spec: specs/continuous-controls.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Resolve signed/provenance-aware policy packs, inheritance, separation of duties, and fail-closed weakening checks.
2. Evaluate supplied receipts across merge, agent-action, deployment, and working-tree events; govern exceptions and drift.
3. Export the Graph Ops chain, deterministic remediation, dossier artifacts, fleet coverage, and read-only projection.
4. Expose the plane through the CLI and verify the contract, unit tests, Graph Ops surface, and full repository suite.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [ ] T1 | slice=factoryline | files=factoryline/continuous_controls.py,tests/test_continuous_controls.py | verify=`python -m pytest tests/test_continuous_controls.py -q -k "provenance or inheritance or weakening"` | Implement canonical hashing, policy-pack validation, inheritance coverage, and fail-closed weakening codes.
- [ ] T2 | slice=factoryline | files=factoryline/continuous_controls.py,tests/test_continuous_controls.py | verify=`python -m pytest tests/test_continuous_controls.py -q -k "drift or exception"` | Implement receipt evaluation, event drift, bounded exceptions, and deterministic remediation.
- [ ] T3 | slice=factoryline | files=factoryline/continuous_controls.py,factoryline/graph_ops.py,tests/test_continuous_controls.py | verify=`python -m pytest tests/test_continuous_controls.py -q -k "graph or dossier or projection"` | Implement Graph Ops chain, JSON/Markdown/Mermaid dossier, fleet coverage, and read-only projection.
- [ ] T4 | slice=factoryline | files=factoryline/cli.py,tests/test_continuous_controls.py | verify=`python -m pytest tests/test_continuous_controls.py -q` | Add `factory controls` commands and assert safe, context-efficient output without release authority.
