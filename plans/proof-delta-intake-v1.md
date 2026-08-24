# Plan: proof-delta-intake-v1
Spec: specs/proof-delta-intake-v1.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Create the source-bound human intake worksheet and confirmation verifier.
2. Bind verified intake to Product Graph and optionally require it for missions.
3. Add deterministic Proof-Delta retry admission, Graph Ops, and local MCP
   projections without execution authority.
4. Test receipt drift, source mismatch, no-evidence retry halts, CLI/MCP
   boundaries, packaging, and release metadata.

## Tasks (atomic — each independently shippable)
- [ ] T1 | slice=. | files=<=4 | verify=`python -m pytest -q tests/test_intake_grill.py` | Add source-bound Intake Grill and named confirmation receipt tests.
- [ ] T2 | slice=. | files=<=4 | verify=`python -m pytest -q tests/test_intake_grill.py tests/test_product_missions.py` | Bind confirmations to Product Graph and enforce optional Mission intake requirement.
- [ ] T3 | slice=. | files=<=4 | verify=`python -m pytest -q tests/test_proof_delta.py tests/test_mission_graph.py` | Add Proof-Delta evidence-gain admission and Mission Graph retry guard.
- [ ] T4 | slice=. | files=<=4 | verify=`python -m pytest -q tests/test_graph_ops.py tests/test_mcp.py` | Project the new facts read-only through Graph Ops and MCP.
- [ ] T5 | slice=. | files=<=4 | verify=`python -m build; python -m twine check dist/*; python -m pytest -q` | Align release documentation and package metadata, then validate the complete release artifact.
