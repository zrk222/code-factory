# Plan: reality-check-v1

Spec: `specs/reality-check-v1.md`
Architect verdict: PASS

## Logical decomposition

1. Define and validate a behavior contract with positive and negative intent assertions before any command executes.
2. Reuse the approved E2E proof runner to produce a hash-bound Reality Check card without generating tests or commands.
3. Project proof cards and named human authorizations into Graph Ops.
4. Add token-bound Studio controls for a one-time Reality Check authorization and a repair-plan review handoff, while retaining all repair and release authority outside Graph Ops.
5. Prove intent validation, hollow detection, stale binding rejection, replay prevention, Graph Ops projection, and loopback endpoint boundaries.

## Tasks

- [ ] T1 | slice=factoryline | files=factoryline/reality_check.py,tests/test_reality_check.py | verify=`python -m pytest -q tests/test_reality_check.py` | Implement manifest validation, inspection, behavior receipt, and deterministic views.
- [ ] T2 | slice=factoryline | files=factoryline/graph_authorization.py,tests/test_graph_authorization.py | verify=`python -m pytest -q tests/test_graph_authorization.py` | Implement named expiry, byte bindings, one-time consumption, and stale-input rejection.
- [ ] T3 | slice=factoryline | files=factoryline/studio.py,factoryline/graph_ops.py,factoryline/graph_ops.html,tests/test_graph_ops.py | verify=`python -m pytest -q tests/test_graph_ops.py tests/test_studio.py` | Render typed proof and authorization nodes and expose confirmation-gated loopback controls.
- [ ] T4 | slice=docs | files=docs/REALITY_CHECK.md,docs/GRAPH_OPS.md,tests/test_graph_ops.py | verify=`python -m pytest -q tests/test_graph_ops.py` | Document novice, team, and enterprise use without unsupported savings claims.
- [ ] T5 | slice=README | files=README.md,tests/test_publication_metadata.py | verify=`python -m pytest -q tests/test_publication_metadata.py` | Add concise public discoverability without unsupported savings claims.
