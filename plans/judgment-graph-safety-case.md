# Plan: judgment-graph-safety-case
Spec: specs/judgment-graph-safety-case.md (must be approved first)
Architect verdict: PASS

## Logical decomposition (phases)
1. Add a strict, JSON-only Judgment Capsule store with explicit proposal,
   independent promotion, reconsideration, and read-only status operations.
2. Compile a deterministic Change Safety Case from explicit changed paths and
   supplied hash-bound obligation receipts; never run a test or infer evidence.
3. Project the active decision contracts into Graph Ops, Studio HTML, MCP, and
   the JetBrains local tool window.
4. Add user-facing concise documentation and test the acceptance boundary,
   package metadata, and local plugin behavior before any target publication.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [x] T1 | slice=judgment-store | files=<=4 | verify=`python -m pytest tests/test_judgment.py -q` | Add strict Capsule validation, proposal, independent promotion, reconsideration, and deterministic status.
- [x] T2 | slice=safety-case | files=<=4 | verify=`python -m pytest tests/test_judgment.py tests/test_graph_ops.py -q` | Add deterministic Change Safety Case routing and active Capsule Graph Ops projection.
- [x] T3 | slice=surfaces | files=<=4 | verify=`python -m pytest tests/test_mcp.py tests/test_graph_ops.py -q` | Add read-only MCP and Graph Ops visual representation with no execution control.
- [x] T4 | slice=jetbrains | files=<=4 | verify=`.\\gradlew.bat test guardianReleaseGate` | Add a local, confirmation-bound inspection path and visible Engineering Judgment panel.
- [x] T5 | slice=release-docs | files=<=4 | verify=`python -m pytest tests/test_publication_metadata.py tests/test_release_integrity.py -q` | Update concise public and reviewer-facing summaries; distinguish local evidence from external publication or review facts.
