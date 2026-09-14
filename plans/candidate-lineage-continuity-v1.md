# Plan: candidate-lineage-continuity-v1
Spec: specs/candidate-lineage-continuity-v1.md (approved)
Architect verdict: PASS | CONCERNS | FAIL

## Logical decomposition (phases)
1. Add optional candidate binding to graph lineage while preserving legacy
   receipt verification, then add the cross-artifact continuity verifier.
2. Expose the strict verifier through the graph CLI and document the claim
   boundary for human and agent reviewers.
3. Run focused and full regression tests plus SpecLine/ForgeLine gates; do not
   publish or deploy.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [x] T1 | slice=specs | files=specs/candidate-lineage-continuity-v1.md,specs/candidate-lineage-continuity-v1.ssat.yaml | verify=`specline strict candidate-lineage-continuity-v1 --root .` | approve the spec and SSAT contract
- [x] T2 | slice=factoryline | files=factoryline/graph_forensics.py | verify=`py -3.11 -m pytest -q tests/test_graph_forensics.py` | bind an optional candidate digest to sealed graph lineage and enforce it when expected
- [x] T3 | slice=tests | files=tests/test_graph_forensics.py | verify=`py -3.11 -m pytest -q tests/test_graph_forensics.py` | prove graph candidate binding, mismatch, and legacy compatibility
- [x] T4 | slice=factoryline | files=factoryline/candidate_lineage.py | verify=`py -3.11 -m pytest -q tests/test_candidate_lineage.py` | verify Oracle, deep-audit, and graph evidence share one current candidate
- [x] T5 | slice=tests | files=tests/test_candidate_lineage.py | verify=`py -3.11 -m pytest -q tests/test_candidate_lineage.py` | kill mixed, stale, unbound, incomplete, authority, and path mutants
- [x] T6 | slice=factoryline | files=factoryline/cli.py | verify=`py -3.11 -m factoryline.cli graph lineage-continuity --help` | add the strict continuity CLI entrypoint
- [x] T7 | slice=docs | files=docs/GRAPH_FORENSICS.md,docs/CANDIDATE_LINEAGE.md | verify=`git diff --check` | document candidate binding and the reviewer claim boundary
- [x] T8 | slice=CHANGELOG.md | files=CHANGELOG.md | verify=`git diff --check` | record candidate continuity without changing release authority
- [x] T9 | slice=smoke | files=smoke/candidate-lineage-continuity-v1.json | verify=`forge verify-tests candidate-lineage-continuity-v1 specs/candidate-lineage-continuity-v1.ssat.yaml --root .` | register the deterministic continuity regression smoke
- [x] T10 | slice=context | files=context/PROGRESS.md | verify=`git diff --check` | record the sealed plan and implementation receipts for handoff
