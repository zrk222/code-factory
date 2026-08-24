# Plan: jetbrains-workspace-advisor

Spec: specs/jetbrains-workspace-advisor.md
Architect verdict: PASS

## Logical decomposition

1. Add one bounded local inspector with deterministic schema, artifact writer,
   and no automatic configuration authority.
2. Route the same facts through CLI and read-only MCP.
3. Add a confirmation-gated JetBrains tab with plain-language boundaries and
   an explicit local report action.
4. Cover normal, bounded, artifact, path-classification, MCP, and schema paths
   with Python/Kotlin tests and update public documentation.

## Tasks (atomic)

- [x] T1 | slice=local-inspector | files=<=4 | verify=`python -m pytest -q tests/test_workspace_advisor.py` | Add deterministic bounded workspace facts and explicit-only local artifacts.
- [x] T2 | slice=cli-mcp | files=<=4 | verify=`python -m pytest -q tests/test_workspace_advisor.py tests/test_mcp.py` | Expose the inspector through CLI and zero-authority MCP.
- [x] T3 | slice=jetbrains-surface | files=<=6 | verify=`.\\gradlew.bat test -x instrumentCode --rerun-tasks --console=plain` | Add confirmation-gated Tool Window and Tools action.
- [x] T4 | slice=public-proof | files=<=6 | verify=`python -m pytest -q` | Add Marketplace-safe docs, strict spec/architecture gates, and end-to-end evidence.
