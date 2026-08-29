# Plan: proof-review-workflow-v1

Spec: `specs/proof-review-workflow-v1.md`

Architect verdict: PASS

## Atomic tasks

- [x] T1 | slice=specs | files=specs/proof-review-workflow-v1.md,specs/proof-review-workflow-v1.ssat.yaml | verify=`specline strict proof-review-workflow-v1 --root .` | Seal the closed routes, authority boundary, input limits, and observable markers.
- [x] T2 | slice=factoryline | files=factoryline/proof_review_workflow.py | verify=`python -m pytest -q tests/test_proof_review_workflow.py -k "intent or trajectory or review or learning or inbox or hook or card"` | Implement the seven deterministic proof-review capabilities.
- [x] T3 | slice=factoryline | files=factoryline/cli.py | verify=`python -m pytest -q tests/test_proof_review_workflow.py -k cli` | Expose one machine-readable proof-review command family.
- [x] T4 | slice=factoryline | files=factoryline/graph_ops.py,factoryline/graph_ops.html | verify=`python -m pytest -q tests/test_proof_review_workflow.py -k graph` | Project a read-only Team Proof Inbox and visual next item.
- [x] T5 | slice=tests | files=tests/test_proof_review_workflow.py | verify=`python -m pytest -q tests/test_proof_review_workflow.py` | Prove every requirement, drift boundary, tamper check, and authority limit.
- [x] T6 | slice=smoke | files=smoke/proof-review-workflow-v1.json | verify=`forge verify-tests proof-review-workflow-v1 specs/proof-review-workflow-v1.ssat.yaml --root .` | Make the native behavior and regression suites release gates.
- [x] T7 | slice=docs | files=docs/PROOF_REVIEW_WORKFLOW.md | verify=`python -m pytest -q tests/test_proof_review_workflow.py` | Document the five-minute path and precise claim boundary.
- [x] T8 | slice=README.md | files=README.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Link one concise agent-neutral front door without expanding the landing-page vocabulary tax.

## Release boundary

This plan writes local repository artifacts only. It does not install vendor
hooks, execute an agent, apply a repair, approve work, publish, deploy, access a
credential, grant a connector, or send a message.
