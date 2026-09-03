# Plan: adoption-simplification
Spec: specs/adoption-simplification.md (must be approved first)
Architect verdict: PASS

## Logical decomposition (phases)
1. Add the read-only, plain-language journey contract and CLI entry point.
2. Put a three-choice Start Here panel before specialized Graph Ops modules.
3. Align public onboarding documentation and verify behavior, rendering markers, and boundaries.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [x] T1 | slice=factoryline | files=factoryline/ide_playbook.py,factoryline/cli.py | verify=`python -m pytest -q tests/test_adoption_guide.py` | Add the journey contract and `factory guide` CLI.
- [x] T2 | slice=tests | files=tests/test_adoption_guide.py | verify=`python -m pytest -q tests/test_adoption_guide.py` | Prove journey selection, primary-action uniqueness, invalid-input refusal, and zero execution authority.
- [x] T3 | slice=factoryline | files=factoryline/graph_ops.html,tests/test_graph_ops.py | verify=`python -m pytest -q tests/test_graph_ops.py` | Add the Start Here panel and deterministic UI markers.
- [x] T4 | slice=docs | files=docs/OVERVIEW.md,docs/CAPABILITY_EVIDENCE.md | verify=`python -m pytest -q tests/test_publication_metadata.py tests/test_adoption_guide.py` | Explain progressive disclosure, maturity boundaries, executable evidence, and the advanced handoff.
- [x] T5 | slice=README.md | files=README.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Replace the public front door with the three plain-language journeys.
