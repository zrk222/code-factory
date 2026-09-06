# Plan: release-decision-visibility-v1
Spec: specs/release-decision-visibility-v1.md
Architect verdict: PASS

## Logical decomposition (phases)

1. Project the existing Mission Control release-workflow facts as one explicit
   zero-authority Graph Ops decision node.
2. Expose the node in the Graph Ops UI lane and describe the same route in the
   IDE playbook without adding an execution control.
3. Prove state selection, provider-unknown boundary, UI discoverability, and
   playbook authority constraints through focused regression tests.

## Tasks (atomic — each independently shippable)

- [x] T1 | slice=release-decision-graph | files=<=4 | verify=`python -m pytest -q tests/test_graph_ops.py tests/test_release_decision.py` | Added the read-only Graph Ops node and deterministic state tests using the existing Mission Control workflow projection.
- [x] T2 | slice=release-decision-playbook | files=<=4 | verify=`python -m pytest -q tests/test_ide_playbook.py tests/test_graph_ops.py` | Added the read-only Graph Ops UI lane and IDE playbook route with explicit no-provider and no-authority wording.
- [x] T3 | slice=release-decision-proof | files=<=4 | verify=`python -m pytest -q tests/test_graph_ops.py tests/test_release_decision.py tests/test_ide_playbook.py tests/test_mcp.py` | Passed focused regression and package integrity checks; remaining gate receipts are recorded in context/PROGRESS.md.
