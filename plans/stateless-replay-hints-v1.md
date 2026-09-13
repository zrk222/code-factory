# Plan: stateless-replay-hints-v1
Spec: specs/stateless-replay-hints-v1.md (approved)
Architect verdict: PASS

## Logical decomposition

1. Derive request and response digests using canonical JSON.
2. Emit safe client retry metadata without server replay state.
3. Mark normal responses cacheable with a bounded TTL and errors/notifications
   non-cacheable.
4. Attach the projection to `dispatch_stateless` and document its boundary.
5. Prove determinism, strict bounds, no I/O, and preserved authority flags.

## Tasks

- [x] T1 | slice=factoryline | files=factoryline/mcp_replay.py,factoryline/mcp.py | verify=`py -3.11 -m pytest -q tests/test_mcp_replay.py tests/test_mcp_stateless.py` | Add replay hints and stateless envelope projection.
- [x] T2 | slice=tests | files=tests/test_mcp_replay.py,tests/test_mcp_stateless.py | verify=`py -3.11 -m pytest -q tests/test_mcp_replay.py tests/test_mcp_stateless.py` | Prove hashes, bounds, cache policy, and no mutation.
- [x] T3 | slice=docs | files=docs/MCP.md,docs/AI_CLIENTS.md | verify=`git diff --check` | Explain client-only retry and cache semantics.
- [x] T4 | slice=CHANGELOG.md | files=CHANGELOG.md | verify=`git diff --check` | Record the release note.
- [x] T5 | slice=forge | files=<=1 | verify=`forge qa stateless-replay-hints-v1 --strict --root .` | Review complexity, security, and intent coverage.
- [x] T6 | slice=smoke | files=smoke/stateless-replay-hints-v1.json | verify=`forge smoke stateless-replay-hints-v1 --root .` | Register non-hollow hint smoke evidence.
- [x] T7 | slice=context | files=context/PROGRESS.md | verify=`git diff --check` | Record final verification and no-publication boundary.
