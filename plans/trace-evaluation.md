# Plan: trace-evaluation
Spec: specs/trace-evaluation.md
Architect verdict: PASS

## Remaining tasks
- [ ] T1 | slice=factoryline | files=factoryline/analysis_evidence.py,tests/test_analysis_evidence.py | verify=`python -m pytest -p no:cacheprovider tests/test_analysis_evidence.py -k span_evaluation` | Bind source-backed span facts and compute numeric, context, silent-result and redundant-call criteria with sabotage controls.
- [ ] T2 | slice=factoryline | files=factoryline/operations.py,tests/test_operations.py | verify=`python -m pytest -p no:cacheprovider tests/test_operations.py -k calibration` | Validate frozen assignments, separate annotations and adjudication, contamination checks, per-category confusion/abstention/agreement/uncertainty.
- [ ] T3 | slice=factoryline | files=factoryline/operations.py,tests/test_operations.py | verify=`python -m pytest -p no:cacheprovider tests/test_operations.py -k sampling` | Add denominator-complete risk sampling, latency/cost quality and hard budgets.
- [ ] T4 | slice=factoryline | files=factoryline/runtime_audit_performance.py,tests/test_runtime_audit.py | verify=`python -m pytest -p no:cacheprovider tests/test_runtime_audit.py -k trace_regression` | Pair exact baseline/candidate trace cohorts and enforce approved quality/cost/tail-latency thresholds.
- [ ] T5 | slice=factoryline | files=factoryline/operations.py,tests/test_operations.py | verify=`python -m pytest -p no:cacheprovider tests/test_operations.py -k rollout_evidence` | Bind observed rollout/rollback controls and apply sticky assignment/SRM only for actual randomized experiments.
- [ ] T6 | slice=factoryline | files=factoryline/jev_classifier.py,factoryline/cli_foundations.py,tests/test_audit_rule_search.py,tests/test_factoryline.py | verify=`python -m pytest -p no:cacheprovider tests/test_factoryline.py -k trace_evaluation` | Wire native CLI/Jev review, versioned rubric and failure-to-case recovery without expanding authority.
- [ ] T7 | slice=factoryline | files=factoryline/mcp.py,factoryline/data/junie_pack.json,factoryline/studio.py,tests/test_agent_contract.py | verify=`python -m pytest -p no:cacheprovider tests/test_agent_contract.py -k trace_evaluation` | Expose agent/Junie/UI measurements with evidence and unknown states, then run an operator trial and update previews only for completed abilities.

- [ ] T8 | slice=factoryline | files=factoryline/adoption.py,factoryline/cli_first_lap.py,tests/test_adoption.py | verify=`python -m pytest -p no:cacheprovider tests/test_adoption.py -k "repo_scan or native_worker"` | Make local deep orchestration native by default and discover workspace worker configuration while retaining authorization.

- [ ] T9 | slice=factoryline | files=factoryline/operations.py,factoryline/adoption.py,tests/test_operations.py,tests/test_adoption.py | verify=`python -m pytest -p no:cacheprovider tests/test_operations.py tests/test_adoption.py -k "telemetry or native_trace"` | Instrument actual local repository orchestration with bounded parent-child telemetry and failure retention.

- [ ] T10 | slice=factoryline | files=factoryline/analysis_evidence.py,factoryline/jev_classifier.py,tests/test_audit_rule_search.py | verify=`python -m pytest -p no:cacheprovider tests/test_audit_rule_search.py -k span_review` | Bind actual semantic task evidence and exact source excerpts, preserving explicit missing-evidence states and provider authority.

- [ ] T11 | slice=factoryline | files=factoryline/jev_classifier.py,tests/test_audit_rule_search.py | verify=`python -m pytest -p no:cacheprovider tests/test_audit_rule_search.py -k span_review_batch` | Partition full review inputs into bounded complete batches and verify exact aggregate response coverage.

- [ ] T12 | slice=scripts | files=scripts/evaluate_jev.mjs,scripts/evaluate_jev.test.mjs | verify=`node --test --test-name-pattern="dispatch budget|budget journal" scripts/evaluate_jev.test.mjs` | Enforce policy-bound admission before live Jev requests, durable reservation events, denied/unscored denominators and unknown/overrun stop conditions.

- [ ] T13 | slice=factoryline | files=factoryline/analysis_evidence.py,tests/test_analysis_evidence.py | verify=`python -m pytest -p no:cacheprovider tests/test_analysis_evidence.py -k applicability` | Bind per-span applicability reasons/source evidence, reject hidden facts, report evaluated and exempt denominators without false PASS.

- [ ] T14 | slice=tests | files=tests/test_architecture_health.py | verify=`python -m pytest -p no:cacheprovider tests/test_architecture_health.py -k large_module_coverage_gaps` | Prove strict file guard detects unpinned oversized production, respects pinned inventory, and fails closed on missing/outside files.

## Delivery evidence
New/changed/failed tests only locally; scoped lint/C901/architecture checks, independent AI source review, hash-bound workflow gate and required CI. Production calibration and rollout evidence require their real authorized environments. File budgets cannot be raised; extract/consolidate existing modules when needed. This plan does not establish implementation or empirical accuracy.

## Concrete architecture decisions
- T1 uses a separate `factory.span-evaluation.v1` envelope in analysis_evidence.py; audit_trace.v1 and its 40-step chain remain unchanged. T1 validates independently bounded telemetry spans against current trace and candidate/source digests, plus explicit tool, model, prompt-template, rubric, dataset and policy identity/version/content digests. It owns all preflight bindings, not later tasks. Each identity references recomputed artifact bytes; caller-declared hashes alone are insufficient. T2-T6 consume this validated binding and reject mismatches or missing mandatory identities. A reviewed applicability declaration is required for a non-model span; no invented model identity is permitted. The 10000-span bound does not increase the existing trace-step bound.
- T2, T3 and T5 modify operations.py sequentially. Do not add code to benchmark_lab.py; read-reuse its existing metric helper where suitable. Annotation evidence, adjudicated labels and judge-only inputs remain distinct. Missing trusted external identity/process attestation leaves independence UNVERIFIED.
- Freeze split assignment before predictions; human labels may precede stratified assignment, check exact evidence duplication across splits, and retain disagreements and abstentions. Constant-label kappa is null with a reason; abstentions reduce coverage rather than count as correct negatives.
- T6 uses `factory journey evaluate-trace` under the existing dispatched journey group, avoiding additions to the capped top-level CLI. Preserve all existing journey commands.
- T4 extends the existing approved paired runtime-performance path. T5 keeps an observed rollout-control receipt distinct from the existing generic canary aggregate. Offline or synthetic evidence cannot authorize a live rollout.
- Validate budget-denied samples, unknown required cost/latency, stale source/policy/model bindings and missing controls as INCOMPLETE or BLOCKED. No missing evidence may become a pass.
- T7 requires an actual operator trial. Static UI fixtures remain NOT_RUN for operator effectiveness and provider behavior.

## Local operator entry points

- CLI: `factory journey evaluate-trace request.json --request-sha256 <sha256-of-request-bytes> --root . --json` evaluates span criteria. Any missing, stale or failing evidence returns a nonzero status.
- MCP: `factory.evaluate_trace` accepts `request_path`, `request_sha256`, and `kind` (`spans`, `calibration`, `sampling`, `regression`, `rollout`). It reads evidence only; it does not call a provider or execute deployment controls.
- A span request uses `factory.span-evaluation.request.v1` with `binding_request` and `spans`. Other evaluator requests are the binding request itself. Every binding names the actual trace, candidate, sources and versioned tool/model/prompt/rubric/dataset/policy artifact bytes by relative path and SHA-256.
- Dashboard: save `.factory/trace-evaluation/latest.json` with schema `factory.trace-evaluation-manifest.v1`, evaluator `kind`, and `request` / `receipt` descriptors (`path`, `sha256`). Results disappear into INCOMPLETE when source, identities, request or result hashes no longer match. Missing measurements stay unknown.
- Calibration additionally binds assignments, annotations, judgments and adjudications. Sampling binds the eligible population and policy. Regression binds baseline, candidate_cohort and regression_policy. Rollout binds rollout and all three observed control artifacts.

## Remaining operational acceptance

The local evaluators and native surfaces are implemented; this is not complete production integration. Remaining acceptance is explicit:
- Capture and validate full parent-child span lineage from actual operator executions, with per-criterion applicability instead of requiring numeric/context/tool facts on every span.
- Run the implemented bounded semantic source/context batching through an authorized provider and calibrate its actual outputs; local packet preparation does not establish semantic correctness.
- Enforce sampling reservations at provider dispatch, then reconcile actual usage and detect longitudinal drift. The present evaluator validates supplied ledgers only.
- Obtain independent labelled evaluation evidence and authenticated production control observations; declared identity/timestamp strings cannot establish independence or live deployment.
- Run a real operator workflow, independent implementation review and the final hash-bound workflow gate before completion/merge. Static rendered fixtures do not prove operator effectiveness.
- Complete the broader approved app-builder mission and update external previews only after the corresponding functionality is proven.

## Semantic evidence input

The optional `semantic_evidence` binding references a local JSON artifact with schema `factory.span-semantic-evidence.v1` and `spans`. Each record contains `span_id`, `task_input`, `task_output`, and 1..8 `references`. A reference contains a bound source `path` and `sha256`, plus a half-open `start_byte` / `end_byte` range. CF reopens and hashes the current source before decoding the exact UTF-8 excerpt. Inputs/outputs are limited to 8192 bytes each; excerpts to 32768 bytes. Duplicate references, unknown spans, invalid ranges and stale source digests are rejected.

The bound rubric additionally supplies 1..8 `semantic_criteria` (`id`, `predicate`). These become unresolved binary claims for the reviewer; receiving source bytes is not a semantic pass. Missing task evidence remains UNKNOWN_MISSING_TASK_EVIDENCE. Raw task/source content is untrusted data and is not sent anywhere by these local builders. Provider execution remains separately authorized. Larger review collections use the bounded batching and complete aggregate coverage protocol below; actual provider acceptance remains open.

Local checkpoint: three CI-failing taxonomy/protocol/inventory tests repaired and passed. The newly observed ABSTAIN, BOUND_LOCAL_EVIDENCE and REGRESSION_GATES strings are observation/dispatch labels, not additional rejection conditions. Ten affected semantic/dashboard checks pass. Scoped Forge QA returns A/PASS with no findings after complexity refactoring; cross-platform CI must confirm the new commit.

### Complete batch review protocol

`build_span_review_batches(root, request)` emits an ordered `factory.span-semantic-review-batches.v1` collection, preserving one full evaluation digest and exact span coverage. Each batch has at most eight spans, 128 claims and 256000 packet bytes. Oversized groups split; a single span exceeding packet limits rejects the request. The complete batch set is limited to 20000000 bytes. Full evaluation spans are not copied into every batch.

`normalize_span_review_batches` revalidates current evidence and the batch-set digest, requires every response in exact context order, and preserves deterministic FAIL/INCOMPLETE plus missing semantic-evidence states. This local protocol prepares evidence; provider calls, budget admission and empirical calibration remain separate unfinished acceptance items.

## Independent review repairs

The review identified four concrete defects, now repaired in source with focused tests: calibration prediction rows bind model/prompt/rubric artifact digests; saved status recomputes the exact bound request; span results include the exact canonical request digest; tool requirement flags reject non-booleans. Failure recovery replays current bindings before creating a case, records the private request digest/span index and before-evidence digest, and supplies four reproducible next actions. Development cases retain their private evidence outside the exported receipt and cannot become holdout data. Holdout label exposure and producer independence remain UNVERIFIED until externally established.

The native evaluator SSAT now enumerates the current analysis, operations and Jev interfaces rather than the older function snapshot. This is an interface inventory, not operational acceptance. Current CI failures must be repaired before merge.

## Pre-edit size admission

Before editing any touched production module or Jev script, measure current normalized UTF-8 bytes and lines against architecture-policy.json. Reserve enough headroom for the proposed change before writing; do not write an oversized intermediate file. Reuse or consolidate existing modules when the change cannot fit, preserving the 460-file cap. The new trace/Jev pins are tighter than the existing discovery ceilings; all older pinned ceilings remain unchanged.

## Native dispatch and applicability checkpoint

The live Jev operator now requires an explicit policy bound to case content and the selected rubric; admissions are synced before requests, denied/halted cases remain in denominators, malformed-answer costs are retained, and unknown usage/overrun stops later dispatch. The policy is per trial and its reference is not authenticated release/spend authority. Exact provider billing ceilings and production approval verification remain separate acceptance requirements.

Optional bound criterion applicability distinguishes NOT_APPLICABLE from PASS, requires current source references and exact coverage, rejects exemptions hiding present facts, and cannot pass a wholly unevaluated trace. New direct dispatch/size-guard tests address the two attribution gaps without changing grading thresholds. Current-head CI and independent final acceptance remain pending.
