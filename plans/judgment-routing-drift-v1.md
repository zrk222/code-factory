# Plan: judgment-routing-drift-v1
Spec: specs/judgment-routing-drift-v1.md (approved)
Architect verdict: PASS

## Logical decomposition
1. Preserve V1 Capsules while adding strict V2 declared judgment metadata and
   hash-bound change-profile validation.
2. Compile deterministic novelty, drift, human-question, and attention facts
   into the existing read-only Safety Case.
3. Carry the bounded facts through the CLI, MCP, Graph Ops, and FactoryLine
   panel; do not add execution or implicit decision controls.
4. Update developer/team/reviewer messaging to explain the result in one
   screen, then run the package/plugin/release gates.

## Tasks
- [ ] T1 | slice=judgment-core | files=<=4 | verify=`python -m pytest tests/test_judgment.py -q` | Add V2 Capsule and canonical declared change-profile validation without changing V1 digest behavior.
- [ ] T2 | slice=safety-routing | files=<=4 | verify=`python -m pytest tests/test_judgment.py tests/test_mcp.py -q` | Emit deterministic attention, novelty, drift, and minimum human questions from supplied facts.
- [ ] T3 | slice=surfaces | files=<=4 | verify=`python -m pytest tests/test_graph_ops.py tests/test_mcp.py -q` | Present concise Change Safety Case facts in Graph Ops and MCP without execution authority.
- [ ] T4 | slice=jetbrains | files=<=4 | verify=`.\\gradlew.bat test guardianReleaseGate` | Render the one-screen review packet in the local FactoryLine Judgment panel.
- [ ] T5 | slice=release-messaging | files=<=4 | verify=`python -m pytest tests/test_publication_metadata.py tests/test_release_integrity.py -q` | Update concise platform/reviewer messaging and versioned release evidence.
