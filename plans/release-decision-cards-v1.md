# Plan: release-decision-cards-v1
Spec: specs/release-decision-cards-v1.md
Architect verdict: PASS

## Logical decomposition (phases)

1. Build the pure decision-card core from existing strict local evidence.
2. Surface the same card coherently in CLI, MCP, and Mission Control.
3. Verify deterministic classification, read-only behavior, package integrity,
   and regression coverage.

## Tasks (atomic — each independently shippable)

- [x] T1 | slice=release-card-core | files=<=4 | verify=`python -m pytest -q tests/test_release_decision.py tests/test_release_integrity.py` | Added the pure Release Decision Card, deterministic rendering, and direct classification tests without any external action.
- [x] T2 | slice=release-card-surfaces | files=<=4 | verify=`python -m pytest -q tests/test_release_decision.py tests/test_mcp.py tests/test_assembly_read_efficiency.py tests/test_deep_audit_surfaces.py tests/test_runtime_audit_surfaces.py tests/test_release_integrity.py` | Added source CLI, MCP, and Mission Control projections of the read-only card and tested authority/input boundaries.
- [x] T3 | slice=release-card-release-proof | files=<=4 | verify=`python -m pytest -q && python -m build && python -m twine check dist/*.whl dist/*.tar.gz` | Ran the regression and package proof and inspected the decision CLI from a clean installed wheel.
