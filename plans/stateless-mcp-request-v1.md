# Plan: stateless-mcp-request-v1
Spec: specs/stateless-mcp-request-v1.md (approved)
Architect verdict: PASS

## Logical decomposition

1. Bound one-shot input shape, size, and workspace path.
2. Reuse the existing read-only MCP dispatcher without adding tools or authority.
3. Return a canonical request digest and explicit no-state claim boundary.
4. Prove deterministic repeatability, rejection, CLI behavior, and no writes.

## Tasks

- [x] T1 | slice=specs | files=specs/stateless-mcp-request-v1.md,specs/stateless-mcp-request-v1.ssat.yaml | verify=`specline strict stateless-mcp-request-v1 --root .` | Seal the one-shot stateless contract.
- [x] T2 | slice=factoryline | files=factoryline/mcp.py,factoryline/cli.py | verify=`py -3.11 -m pytest -q tests/test_mcp_stateless.py` | Implement bounded request dispatch and root-relative CLI input.
- [x] T3 | slice=tests | files=tests/test_mcp_stateless.py | verify=`py -3.11 -m pytest -q tests/test_mcp_stateless.py tests/test_mcp.py tests/test_mcp_setup.py` | Prove stable digest, rejection markers, notifications, CLI, and no workspace writes.
- [x] T4 | slice=docs | files=docs/MCP.md,docs/AI_CLIENTS.md | verify=`git diff --check` | Document the stateless path and its non-goals.
- [x] T5 | slice=CHANGELOG.md | files=CHANGELOG.md | verify=`git diff --check` | Record the stateless request and rule-search additions.
- [x] T6 | slice=forge | files=<=1 | verify=`forge qa stateless-mcp-request-v1 --strict --root .` | Review complexity, scope, and quality evidence.
- [x] T7 | slice=factoryline | files=factoryline/mcp.py,factoryline/cli.py,factoryline/audit_rule_search.py | verify=`ruff check factoryline/mcp.py factoryline/audit_rule_search.py` | Run native lint on the implementation boundary.
- [x] T8 | slice=tests | files=tests/test_mcp_stateless.py,tests/test_audit_rule_search.py | verify=`py -3.11 -m pytest -q tests/test_mcp_stateless.py tests/test_audit_rule_search.py` | Prove digest, rule discovery, rejection markers, CLI, and no writes.
- [x] T9 | slice=smoke | files=smoke/stateless-mcp-request-v1.json | verify=`forge smoke stateless-mcp-request-v1 --root .` | Register a non-hollow one-shot smoke check.
- [x] T10 | slice=context | files=context/PROGRESS.md | verify=`git diff --check` | Record final evidence and publication boundary.
