# Plan: developer-verification
Spec: specs/developer-verification.md (approved before implementation)
Architect verdict: PASS

## Tasks (atomic — each independently shippable)
- [ ] T1 | slice=factoryline | files=factoryline/product_missions.py,factoryline/mission_graph.py,factoryline/graph_ops.py | verify=`ruff check factoryline/product_missions.py factoryline/mission_graph.py factoryline/graph_ops.py` | Extend existing criterion evidence validation with typed case/input/output/challenge and proof-disposition joins; require integrity-valid AND complete receipts at graph completion gates; missing or stale required evidence remains incomplete.
- [ ] T2 | slice=factoryline | files=factoryline/adoption.py,factoryline/cli_review_surfaces.py | verify=`ruff check factoryline/adoption.py factoryline/cli_review_surfaces.py` | Render a source-current mission completion summary through existing review surfaces with unfinished scope and one next action.
- [ ] T3 | slice=factoryline | files=factoryline/agent_proof_bridge.py,factoryline/analysis_evidence.py | verify=`ruff check factoryline/agent_proof_bridge.py factoryline/analysis_evidence.py` | Import supported local external review claims through existing normalization, deduplicate claim identity and bind evidence-backed dispositions without assuming vendor API or export support.
- [ ] T4 | slice=tests | files=tests/test_product_missions.py,tests/test_mission_graph.py,tests/test_graph_ops.py | verify=`python -m pytest -q tests/test_product_missions.py -k verification tests/test_mission_graph.py tests/test_graph_ops.py` | Add affected positive, missing, malformed, stale, duplicate and infrastructure-failure controls; prove legacy integrity-valid/incomplete receipts cannot complete graphs or verify requirements, without rerunning unrelated passed suites.
- [ ] T7 | slice=tests | files=tests/test_adoption.py,tests/test_agent_proof_bridge.py | verify=`python -m pytest -q tests/test_adoption.py tests/test_agent_proof_bridge.py` | Add focused coverage for completion-summary rendering and normalized external review claims, preserving source-current, duplicate and evidence-backed disposition requirements.
- [ ] T5 | slice=docs | files=docs/DAILY_DRIVER_UPGRADE.md | verify=`git diff --check` | Document verified daily workflow behavior and explicit current limits using existing product vocabulary.
- [ ] T6 | slice=factoryline | files=factoryline/product_missions.py,factoryline/runtime_audit_runner.py,factoryline/pytest_readiness.py,tests/test_product_missions.py | verify=`ruff check factoryline/product_missions.py factoryline/runtime_audit_runner.py factoryline/pytest_readiness.py tests/test_product_missions.py` | Connect approved mission case execution to the existing local production-mutation capture runner. Distinguish CF-observed local execution from imported signer claims; preserve natural assertion, complete catalog, current source, cleanup and no-release-authority boundaries.
- [ ] T8 | slice=factoryline | files=factoryline/product_missions.py,tests/test_product_missions.py | verify=`python -m pytest -q tests/test_product_missions.py -k 'native_gate or local_mutation_capture'` | Verify typed unit, requirement-mutation and receipt-trace observations from the existing native local capture receipts and pytest lifecycle/catalog. Bind each to immutable mission criterion, pre-capture case contract, candidate/source manifest and target/control digest chain; reject generic `passed` evidence, cross-links, stale/tampered receipts and unsupported gates. Close and verify remain read-only.

## Evidence semantics

## Applied-change continuation (H10)

- [ ] T9 | slice=factoryline | files=factoryline/proof_worklog.py,factoryline/adoption.py | verify=`ruff check factoryline/proof_worklog.py factoryline/adoption.py` | Add the source-bound applied-change projection to private completion cards using explicit baseline and current candidate bindings. Capture add/modify/delete/rename facts, literal paths, before/after digests, unrelated edits and declared rationale. Keep unbound deletions, mixed edits and unavailable or stale Git evidence unverified; preserve independent final freshness checks, existing completion semantics and authority boundaries. Use no new module or size-cap increase.
- [ ] T10 | slice=tests | files=tests/test_proof_worklog.py,tests/test_adoption.py | verify=`python -m pytest -q tests/test_proof_worklog.py tests/test_adoption.py -k applied_change` | Add affected controls for explicit-baseline changes, candidate-bound additions, unbound deletions, renames, dirty unrelated paths, same-file ambiguity, stale candidate or HEAD, missing/nonancestor baseline, non-Git roots, literal pathspec characters, symlinks and resource exhaustion. Assert declared rationale is quoted and never fabricated; invalid evidence must not reveal private task details or claim applied work.

T9/T10 bounds: 10 seconds per Git child, 30 seconds total, 1000 paths and 8 MiB retained data. Do not regenerate completed T1–T8 execution evidence for this packet. Completed delivery remains in PR #247/#248 and their receipts; this continuation does not reopen it.

## Evidence semantics (continued)

- A signed v3 oracle verifies the pinned signer's statements and their source,
  environment, test, case and assertion bindings. Signature validation alone
  does not independently establish execution or mutation accuracy.
- Imported E2E results establish only their supported command-pair observations;
  a nonzero process exit is not automatically an intended behavioral failure.
- T1 remains partial until the intended positive execution path and incomplete
  downstream behavior are verified. Do not remove mandatory gaps or relabel
  validated claims as executed behavior to manufacture completion.
- T6 reuses `capture_local_production_mutation` and its existing observation
  route. Local supervised execution is neither independent attestation nor
  application correctness, and must remain labelled with that scope.

Existing integration map: `.factory/harness-efficiency-review/daily-verification-integration-map.md`.
Sequence: finish and deliver native database context, then execute these packets.
The full goal remains open; these tasks join the accepted H2/H10 and community criteria.
