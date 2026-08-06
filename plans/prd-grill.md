# Plan: prd-grill
Spec: specs/prd-grill.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Expose a no-write Product Graph analysis and derive a bounded PRD decision frontier.
2. Write source-bound JSON and Markdown clarification artifacts through a local CLI.
3. Test deterministic ordering, deferred dependencies, source immutability, and invalid-input rejection.
4. Update public and editor surfaces with evidence-safe activation copy.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [x] T1 | slice=prd-analysis | files=<=4 | verify=`python -m pytest -q tests/test_prd_grill.py` | Add no-write Product Graph analysis and deterministic PRD Grill artifact generation.
- [x] T2 | slice=prd-cli | files=<=4 | verify=`python -m pytest -q tests/test_prd_grill.py tests/test_product_missions.py` | Add the bounded local CLI with JSON output and confirmation handling.
- [x] T3 | slice=public-surfaces | files=<=4 | verify=`python -m pytest -q tests/test_publication_metadata.py` | Update root, editor, and Marketplace-facing documentation with truthful PRD Grill activation copy.
- [x] T4 | slice=release-proof | files=<=4 | verify=`python -m pytest -q` | Run strict specifications, architecture checks, full suite, and prepare a reviewed PR.
