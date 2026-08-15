# Plan: proofsearch-v1
Spec: specs/proofsearch-v1.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Seal the bounded counterfactual comparison contract.
2. Verify candidate evidence and deterministic ranking.
3. Expose read-only CLI and Graph Ops controls.
4. Prove rejection behavior, packaging, and public claims.

## Tasks (atomic - each independently shippable)
- [ ] T1 | slice=factoryline | files=factoryline/proofsearch.py | verify=`python -m pytest -q tests/test_proofsearch.py` | Implement bounded plan creation, evidence verification, deterministic total ordering, authority denial, and sealed evaluation verification.
- [ ] T2 | slice=factoryline | files=factoryline/cli.py | verify=`python -m pytest -q tests/test_proofsearch.py` | Expose proofsearch plan, evaluate, and verify commands without execution authority.
- [ ] T3 | slice=factoryline | files=factoryline/graph_ops.py,factoryline/graph_ops.html | verify=`python -m pytest -q tests/test_proofsearch.py tests/test_graph_ops.py` | Add ProofSearch graph nodes, Counterfactual Arena, winner rationale, evidence export, guardrail validation, and a disabled apply control.
- [ ] T4 | slice=docs | files=docs/PROOFSEARCH.md,docs/GRAPH_OPS.md,docs/RELEASE_NOTES_0.32.0.md | verify=`python -m pytest -q tests/test_proofsearch.py tests/test_graph_ops.py` | Document boundaries, commands, UI, measured-savings policy, release notes, and community updates.
- [ ] T5 | slice=pyproject.toml | files=pyproject.toml | verify=`python -m build` | Synchronize Python release metadata.
- [ ] T6 | slice=factoryline | files=factoryline/__init__.py | verify=`python -m pytest -q tests/test_publication_metadata.py` | Synchronize the runtime version.
- [ ] T7 | slice=.github/workflows | files=.github/workflows/publish.yml | verify=`python -m pytest -q tests/test_publication_metadata.py` | Package the verified Graph Ops screenshots with the public release.
