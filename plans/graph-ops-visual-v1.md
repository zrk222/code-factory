# Plan: graph-ops-visual-v1

Spec: specs/graph-ops-visual-v1.md (approved)
Architect verdict: PASS

## Logical decomposition

1. Compile existing local artifacts into one hash-stable typed result.
2. Expose the result through a read-only CLI and authenticated local endpoint.
3. Add the visual Graph Ops Studio page and an accessible live interaction.
4. Prove graph semantics, authority limits, API access, UI contract, and visual quality.

## Tasks

- [ ] T1 | slice=factoryline | files=factoryline/graph_ops.py,tests/test_graph_ops.py | verify=`python -m pytest -q tests/test_graph_ops.py` | Compile bounded, deterministic typed graph snapshots from existing artifacts.
- [ ] T2 | slice=factoryline | files=factoryline/cli.py,factoryline/graph_ops.py,tests/test_graph_ops.py | verify=`python -m pytest -q tests/test_graph_ops.py tests/test_factoryline.py` | Add the read-only `factory graph ops` command.
- [ ] T3 | slice=factoryline | files=factoryline/studio.py,factoryline/graph_ops.html,tests/test_studio.py | verify=`python -m pytest -q tests/test_studio.py` | Serve an authenticated loopback Graph Ops visual with no execution authority.
- [ ] T4 | slice=docs | files=docs/GRAPH_OPS.md | verify=`python -m pytest -q tests/test_graph_ops.py` | Document the unified graph contract and operator workflow.
- [ ] T5 | slice=adr | files=adr/graph-ops-unification-v1.md | verify=`python -m pytest -q tests/test_graph_ops.py` | Record the graph authority boundary.
- [ ] T6 | slice=README.md | files=README.md | verify=`python -m pytest -q tests/test_graph_ops.py` | Add the Graph Ops quick-start.
- [ ] T7 | slice=pyproject.toml | files=pyproject.toml | verify=`python -m build` | Synchronize the package version and Graph Ops template data.
- [ ] T8 | slice=factoryline | files=factoryline/__init__.py | verify=`python -m pytest -q tests/test_graph_ops.py` | Synchronize the runtime version.
- [ ] T9 | slice=tests | files=tests/test_publication_metadata.py | verify=`python -m pytest -q tests/test_publication_metadata.py` | Enforce public release metadata synchronization.
- [ ] T10 | slice=factoryline/cli.py | files=factoryline/cli.py,tests/test_factoryline.py | verify=`python -m pytest -q tests/test_factoryline.py -k mvp` | Add the outcome-first `factory mvp` command with one bounded local web starter, clear next-proof guidance, and unchanged promotion authority.
- [ ] T11 | slice=factoryline | files=factoryline/studio.py | verify=`python -m pytest -q tests/test_studio.py -k dual_track` | Make Studio default to a clearly labelled Instant MVP path while retaining a visible Professional workflow route into Graph Ops and governed controls.
- [ ] T12 | slice=tests | files=tests/test_factoryline.py,tests/test_studio.py,tests/test_publication_metadata.py | verify=`python -m pytest -q tests/test_factoryline.py tests/test_studio.py tests/test_publication_metadata.py` | Prove novice starter containment, expert-path discovery, editor/public docs, and no grant of external-effect authority.
- [ ] T13 | slice=docs | files=docs/START_HERE.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Publish the novice-to-professional-to-enterprise progression without changing the proof or authority boundaries.
- [ ] T14 | slice=factoryline | files=factoryline/graph_ops.py,factoryline/cli.py,tests/test_graph_ops.py | verify=`python -m pytest -q tests/test_graph_ops.py -k impact` | Add exact read-only changed-path impact analysis over explicit proof input edges and emit a minimal stale-only rerun set.
