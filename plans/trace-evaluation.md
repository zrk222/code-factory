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
- Supply actual semantic source/context evidence to the Jev judge with bounded chunking; current span packets validate recorded criterion summaries and do not establish independent semantic correctness.
- Enforce sampling reservations at provider dispatch, then reconcile actual usage and detect longitudinal drift. The present evaluator validates supplied ledgers only.
- Obtain independent labelled evaluation evidence and authenticated production control observations; declared identity/timestamp strings cannot establish independence or live deployment.
- Run a real operator workflow, independent implementation review and the final hash-bound workflow gate before completion/merge. Static rendered fixtures do not prove operator effectiveness.
- Complete the broader approved app-builder mission and update external previews only after the corresponding functionality is proven.
