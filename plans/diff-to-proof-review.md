# Plan: diff-to-proof-review
Spec: specs/diff-to-proof-review.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Build a deterministic change-review controller from existing proof, graph,
   coverage, and risk functions.
2. Expose the controller through an analysis-only `factory change review` CLI.
3. Render an optional local reviewer packet and Mermaid impact map.
4. Prove exact path validation, no-write default behavior, fact preservation,
   optional-artifact containment, and full regression safety.

## Tasks (atomic — each independently shippable)
- [x] T1 | slice=review-controller | files=<=4 | verify=`python -m pytest -q tests/test_change_review.py` | Add deterministic Diff-to-Proof analysis, findings, and renderers over existing Graph Ops, coverage, and risk facts.
- [x] T2 | slice=review-cli | files=<=4 | verify=`python -m pytest -q tests/test_change_review.py` | Add `factory change review` with explicit changed paths, Git base discovery, JSON output, and optional local artifact output.
- [x] T3 | slice=public-docs | files=<=4 | verify=`python -m pytest -q tests/test_publication_metadata.py` | Document the analysis-only review flow and its authority boundary.
- [x] T4 | slice=release-proof | files=<=4 | verify=`python -m pytest -q` | Run strict spec and architecture gates, focused mutation checks, full suite, and receipt-backed review.
