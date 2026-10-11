# Plan: context-efficiency-v1

Spec: specs/context-efficiency-v1.md
Architect verdict: PASS

## v1.1 scoped extension status

- [x] Explicit-candidate selection, progressive budgets, required paths/roles, and omission reasons are implemented in `factoryline/context_efficiency.py`.
- [x] Selected-source construction reuses the exact bounded source snapshot collected during candidate ranking; explicit verification rereads sources for freshness.
- [x] Python candidates include bounded syntactic definitions/imports/calls/identifiers and shared-identifier cross-candidate references. Parse input is capped at 64 KiB and large sources are marked `PARSE_LIMIT`. This is static syntax evidence, not a resolved call graph or runtime behavior claim. Non-Python files are marked `NOT_PARSED`; ranking/rationale is marked unverified heuristic metadata.
- [x] Paired observation evaluation is record-only. It requires matching task/revision/model/tools/budget/rubric identifiers, all context-gathering/coding/repair elapsed phases, complete quality measurements, and at least three pairs before evaluating the 50% elapsed-time target. The target remains unverified operator-supplied evidence.
- [x] The status projection returns aggregate cache metadata and the paired result while marking cached source evidence `UNVERIFIED`; it reports no reusable or current packet count without a fresh verification run.
- [x] Explicit packet verification recomputes excerpts and byte accounting from current source bytes and normalized budgets; re-sealed excerpt tampering is blocked and rejected from cache reuse. Selection ranking/rationale is explicitly unverified heuristic metadata.
- [ ] Focused tests and architecture/workflow receipts must pass on the final candidate before closeout.

- [x] T1 | slice=specs | files=specs/context-efficiency-v1.md | verify=`specline strict context-efficiency-v1 --root .` | Define exact bounded request, packet, verification, and status schemas.
- [x] T2 | slice=factoryline | files=factoryline/context_efficiency.py | verify=`py -3.11 -m pytest -q tests/test_context_efficiency.py -k cache` | Reuse only identical request and source observations with a content-addressed cache.
- [x] T3 | slice=factoryline | files=factoryline/context_efficiency.py | verify=`py -3.11 -m pytest -q tests/test_context_efficiency.py -k drift` | Fail closed on tamper, traversal, symlinks, secrets, and source drift.
- [x] T4 | slice=factoryline | files=factoryline/cli.py,factoryline/mission_control_status.py,factoryline/graph_ops.py,factoryline/mcp.py | verify=`py -3.11 -m pytest -q tests/test_mcp.py tests/test_assembly_read_efficiency.py` | Expose bounded read-only status without changing the seven-reader timing baseline.
- [x] T5 | slice=factoryline | files=factoryline/webmcp.py | verify=`py -3.11 -m pytest -q tests/test_webmcp.py` | Expose the same bounded status through progressive WebMCP.
- [x] T6 | slice=tests | files=tests/test_context_efficiency.py | verify=`py -3.11 -m pytest -q tests/test_context_efficiency.py` | Cover truncation, secrets, bounds, cache reuse, source drift, status, and read-only behavior.
- [x] T7 | slice=docs | files=docs/CONTEXT_EFFICIENCY.md | verify=`git diff --check` | Document the token-estimation boundary and exact local workflow.

Architect verdict: PASS

## Explicit non-goals

- No provider/model invocation or exact token billing measurement.
- No test execution, approval, repair, release, publication, or deployment.
