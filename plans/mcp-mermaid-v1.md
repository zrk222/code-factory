# Plan: mcp-mermaid-v1

Spec: specs/mcp-mermaid-v1.md (approved)
Architect verdict: PASS

## Logical decomposition

1. Build a stdio-only MCP adapter over native Graph Ops functions.
2. Expose that adapter through a local CLI status/serve boundary.
3. Add one shared deterministic Mermaid output-map writer.
4. Apply the writer to target compilation and app-builder outputs.
5. Prove protocol parity, denials, map completeness, hash binding, and package
   behavior through focused, full, and architecture gates.
6. Prepare an immutable-tag, human-controlled Open VSX distribution lane for
   the existing VS Code extension.

## Tasks

- [x] T1 | slice=factoryline | files=factoryline/mcp.py,tests/test_mcp.py | verify=`python -m pytest -q tests/test_mcp.py` | Implement a stdio-only JSON-RPC MCP dispatcher over Graph Ops status, snapshot, impact, and recommendation functions.
- [x] T2 | slice=factoryline | files=factoryline/cli.py,factoryline/mcp.py,tests/test_mcp.py | verify=`python -m pytest -q tests/test_mcp.py tests/test_factoryline.py` | Add `factory mcp status|serve` with no non-stdio transport and no workspace mutations.
- [x] T3 | slice=factoryline | files=factoryline/output_map.py,factoryline/target_compiler.py,tests/test_target_compiler.py | verify=`python -m pytest -q tests/test_target_compiler.py` | Write a deterministic complete Mermaid map and bind it into target compile receipts.
- [x] T4 | slice=factoryline | files=factoryline/output_map.py,factoryline/app_builder.py,tests/test_factoryline.py | verify=`python -m pytest -q tests/test_factoryline.py` | Emit the same map for independent app-builder outputs and return its digest.
- [x] T5 | slice=docs | files=docs/MCP.md,docs/TARGET_COMPILER.md,docs/OVERVIEW.md | verify=`python -m pytest -q tests/test_mcp.py tests/test_target_compiler.py` | Document the inspection-only MCP contract and generated-map boundary.
- [x] T6 | slice=adr | files=adr/factory-mcp-v1.md | verify=`python -m pytest -q tests/test_mcp.py` | Record the authority boundary.
- [x] T7 | slice=smoke | files=smoke/mcp-mermaid-v1.json | verify=`forge verify-tests mcp-mermaid-v1 specs/mcp-mermaid-v1.ssat.yaml --root .` | Prove the behavior tests are non-hollow.
- [x] T8 | slice=.github | files=.github/workflows/openvsx.yml,tests/test_publication_metadata.py | verify=`python -m pytest -q tests/test_publication_metadata.py` | Package an immutable-tag Open VSX candidate, bind its SHA-256, and require protected-environment review plus a scoped publisher token before publication.
- [x] T9 | slice=docs | files=docs/OPENVSX.md | verify=`python -m pytest -q tests/test_publication_metadata.py` | Document the guarded Open VSX publication boundary and the prepared-not-published status.
