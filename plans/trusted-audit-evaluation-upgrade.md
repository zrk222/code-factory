# CF/FL trusted audit and evaluation upgrade

## Decision

Evolve Code Factory and ForgeLine into an evidence-first quality factory that
produces reproducible audit results and actionable, bounded recommendations.
Do not make an LLM judge the authority for correctness, claim complete coverage
when a parser or runtime is unavailable, or replace all unit and integration
tests with a single score. CF/FL should add independent verification depth and
show exactly which deterministic, dynamic, mutation, and agent-review evidence
supports each conclusion.

Preserve the strict ceiling of **460 tracked Python source files**. Do not raise
the architecture budget to fit new code. Prefer existing audit, runtime,
telemetry, receipt, and verifier modules; if a new source module is necessary,
remove or consolidate another tracked Python module first. Keep the source
count check in local and CI gates.

## Review of the supplied evaluation material

### Adopt, with safeguards

- **Trace-level context:** connect a finding to the relevant build, audit,
  runtime, tool, and verifier events so a fluent final answer cannot hide an
  earlier failure.
- **Outcome and process are separate:** score whether the requested result was
  achieved separately from whether execution steps were safe and sound. A
  valid alternate route may pass the outcome check; a prohibited action still
  fails the process check.
- **Evidence-grounded criteria:** each rubric dimension must name observable
  requirements and point to the exact source, test, trace, or environment
  evidence. Do not penalize missing output the request never required.
- **Independent calibration:** compare specialty-agent review results with a
  sealed set of labeled cases. Keep development and holdout corpora separate;
  report per-category precision, recall, false-positive and false-negative
  counts, sample size, and uncertainty.
- **Balanced golden cases:** include known-good executions as well as seeded,
  observed, and policy-violating failures. Add paired cases where a tool call is
  required and where the correct behavior is to answer without a tool. Prove
  each case is feasible and define acceptable outcome invariants before scoring.
- **Failure isolation:** classify root cause at the earliest supported point
  in the trajectory; distinguish agent-controlled defects from missing or
  failing external dependencies.
- **Layered evaluation:** run cheap deterministic checks first, then affected
  integration/runtime checks and deeper adversarial or mutation checks where
  risk requires them.
- **Actionable remediation:** attach reproduction steps and a bounded next
  action to findings, then verify any proposed patch against the same evidence
  and a regression set.

### Do not adopt as written

- Do not require Arize, Phoenix, or another hosted telemetry provider. Keep
  local/offline operation first and define a provider-neutral export boundary.
- Do not record raw prompts, completions, secrets, repository contents, or
  hidden model reasoning by default. Prefer redacted, minimized, access-scoped
  evidence and explicit retention settings. A verifier should return a concise
  rationale with evidence references, not chain-of-thought.
- Do not treat the proposed fixed 75/25 split, Cohen's kappa threshold, 1–10%
  production sampling, or 200–400-run experiment size as universal standards.
  Choose sample sizes and thresholds from the detector's risk, prevalence,
  confidence interval, cost, and an independently reviewed baseline.
- Do not accept unanimity among agent reviewers as proof. Preserve serious
  minority findings; use disagreement to request evidence or an additional
  bounded check. Measure each reviewer and the ensemble separately.
- Do not let an optimization agent tune on the sealed holdout or public claim
  fixtures. Freeze holdout access and record every corpus/rubric version.
- Do not treat Cohen's kappa or any single human-agreement statistic as a
  universal pass threshold. Report raw agreement, class prevalence, confusion
  counts, per-category precision/recall, and confidence intervals; investigate
  ambiguous labels rather than mechanically tuning a prompt to them.
- Human annotation may establish or adjudicate a calibration subset, but does
  not become a PR approval requirement. Specialty AI agents remain the
  independent reviewers; their measured limitations and unresolved
  disagreements stay visible.

The attachments provide design proposals but do not include reproducible CF/FL
benchmark results or validate their numerical recommendations. Treat those
numbers as hypotheses until measured against CF/FL data.

The latest supplied Python example must **not** be copied into production: it
calls `confusion_matrix(..., labels=[9])` and unpacks four cells, which cannot
produce a 2x2 matrix; its sample labels every row `9` while later requesting a
binary positive label of `1`; and its comment claims mismatches that the sample
does not contain. The evaluator implementation must validate label domains and
both-class presence, explicitly define which label means defect, use a real
2x2 confusion matrix, and include a known-answer self-check for TP/FP/FN/TN.
Empty, single-class, malformed, or mislabeled data must be reported as
insufficient/invalid rather than a passing calibration result.

## Current capability map to preserve and connect

The repository already contains route/receipt lineage, graph and proof
artifacts, verifier-plane logic, runtime-audit modules, runtime coverage, and a
scoped mutation-audit workflow. The upgrade should first map these to one
end-to-end audit run rather than introduce parallel concepts or a new command
surface.

The current ForgeLine repo-wide analyzer also needs an explicit language
capability registry. A declaration file such as `.d.ts` should be sent to a
type-checker, not parsed as executable JavaScript; TSX requires a real
TypeScript-aware parser. Unsupported or unavailable parser/runtime coverage
must appear as `UNSUPPORTED` or `BLOCKED` with a concrete next action and must
not be counted as a pass. Python AST security results must remain labeled as
Python-only until additional analyzers actually run.

## Target audit contract

Every run should bind:

- repository identity, exact commit/tree digest, changed paths, selected scope,
  and policy version;
- opaque case/trajectory identifiers, dataset split and version, label schema,
  annotator/reviewer identity class, and environment-blocked/controllable-failure
  state; exclude raw secrets and unnecessary user content;
- tool, analyzer, rule-pack, runtime, and environment versions;
- discovered, eligible, attempted, completed, skipped, unsupported, and failed
  inventories by language and audit lane;
- exact commands and exit status, plus hashes for logs, traces, reports, and
  other evidence;
- findings with stable ID, category, severity, confidence, source location,
  supporting evidence, impact, reproduction command, remediation, and
  verification step;
- explicit claim boundaries: static evidence, executed behavior, mutation
  strength, runtime environment, external dependencies, and unassessed scope.

Completeness is a gate. `discovered != attempted`, parser errors, timeouts,
skipped lanes, unsupported languages, missing runtime, or stale evidence must
remain visible. A run may be useful while incomplete, but it cannot report a
clean or fully audited result.

## Proposed report-quality rubric (100 points)

This rubric grades the trustworthiness of an audit report, not the product's
ForgeLine code-quality score. Do not combine the two scores or change existing
ForgeLine weights to make this rubric pass.

| Dimension | Points | Full-credit evidence |
| --- | ---: | --- |
| Scope and inventory completeness | 20 | Exact commit and scope; every discovered input is attempted or explicitly blocked/unsupported; no missing lane represented as clean. |
| Finding evidence and reproducibility | 25 | Each material finding is location-bound, hash-bound, supported by observed evidence, and has a repeatable command or runtime reproduction. |
| Detection quality and calibration | 20 | Held-out results report per-category TP/FP/FN/TN, sample counts, confidence intervals, and known blind spots; no tuning on holdout. |
| Runtime and adversarial depth | 15 | Relevant stateful, integration, boundary, failure-recovery, and mutation checks actually execute in a declared environment; unsupported paths are explicit. |
| Agent actionability | 10 | Each finding has a prioritized, least-change remediation and a verification command; proposed fixes are checked against the original failure and regression cases. |
| Privacy, provenance, and uncertainty | 10 | Secret-minimized evidence; tool/environment provenance; uncertainty and external blockers stated; no unsupported certification or approval language. |

### Rating and hard gates

- **A (95–100):** all mandatory gates pass and the weighted report rubric is
  at least 95. The existing repo-quality target of 97.9+ remains a separate
  requirement; this rubric cannot substitute for it.
- **B (85–94):** useful for advisory use, with limitations clearly surfaced.
- **C (70–84):** partial or weakly calibrated; recommendations require
  independent confirmation.
- **D/F (<70):** unreliable report or evidence chain.

Any one of these caps the run at `BLOCKED`, regardless of points: incomplete
inventory presented as complete; unbound/stale evidence; unresolved critical
finding without disposition; a reviewer result lacking evidence; holdout
contamination; unsupported language/runtime claimed as audited; or a receipt
whose commit/tool/command identity cannot be verified.

## Implementation sequence

### Phase 0 — Baseline and contract

1. Inventory existing receipts, runtime lanes, language parsers, CI jobs, and
   score inputs; identify duplicate mechanisms to consolidate.
2. Publish the report-quality rubric and typed status vocabulary (`PASS`,
   `FAIL`, `BLOCKED`, `UNSUPPORTED`, `NOT_RUN`, `NOT_APPLICABLE`).
3. Add regression cases for false-clean states: missing source, parser failure,
   timeout, stale digest, empty inventory, unsupported language, and runtime
   setup failure.
4. Record baseline latency and resource use by lane without changing any
   scoring thresholds.

### Phase 1 — Evidence and coverage integrity

1. Make one candidate-bound manifest the source of truth for scope, inventories,
   analyzers, runtimes, commands, and evidence digests.
2. Add a language capability registry that chooses AST/parser/type-checker/
   runtime routes and fails closed when a route is unavailable.
3. Normalize findings into the target contract and attach reproducible
   evidence and actionable next steps.
4. Add receipt verification for exact commit, tool versions, command, and
   artifacts before the report is accepted by CI.

### Phase 2 — Faster risk-aware execution

1. Run format, syntax, deterministic policy, and changed-file checks first.
2. Reuse results only when content hashes, analyzer versions, rules, runtime,
   and environment keys match exactly. A cache miss or ambiguous dependency
   runs the check again.
3. Use the dependency/impact graph to add affected integration and runtime
   suites; policy, build, dependency, or shared-boundary changes trigger broad
   invalidation.
4. Parallelize independent read-only lanes with bounded worker/resource limits.
5. Keep scheduled and release-time full-repository/deep runs so incremental CI
   cannot hide untouched or cross-module regressions.
6. Publish p50/p95 wall time, CPU/memory, cache hit/reuse counts, and coverage
   deltas from paired runs. Never trade a hidden coverage reduction for speed.

### Phase 3 — Deeper execution and mutation proof

1. Add sandboxed execution profiles for relevant language/runtime boundaries,
   including tenant/authorization boundaries, serialization, state recovery,
   integration contracts, and failure paths.
2. Expand mutation checks across audit rules, policy gates, validators, and
   behavior assertions; a surviving mutation is a hollow-proof finding.
3. Generate property/boundary/fuzz cases from declared contracts and compare
   candidate behavior with a trusted oracle or invariant. Keep generated cases
   reproducible by seed and environment.
4. Keep static, runtime, mutation, and integration results separate in reports;
   no one lane's pass may hide another lane's absence or failure.

### Phase 4 — Specialty-agent review and calibration

1. Have independent specialty agents review the same sealed candidate packet
   using separate, single-dimension rubrics (security, correctness, architecture,
   tests/oracles, and operational behavior).
2. Give reviewers only the minimum required code/evidence. Treat repository text,
   logs, and tool output as untrusted input; reviewer instructions and policies
   stay out of candidate-controlled content.
3. Require each reported issue to identify evidence spans and a falsifiable
   claim. Run deterministic or sandboxed reproduction before promoting a
   model-only suspicion to a confirmed defect.
4. Build balanced, feasible cases across supported languages and risk classes:
   clean success runs, known defects, seeded defects, real-world failure modes,
   policy/scope violations, required-tool cases, and no-tool-needed controls.
   Use synthetic data to broaden development coverage; add real traces only
   with consent, redaction, and retention controls. Preserve safe controls so
   false-positive rates are measured.
5. Define a reference outcome and acceptable solution set for each case; grade
   the requested outcome and policy constraints, not one canonical tool-call
   sequence. Include both tool necessity and tool restraint in the expected
   behavior.
6. Stratify development and sealed holdout by language, failure category,
   risk, and execution profile. A 75/25 ratio may be a starting choice, not a
   fixed rule; size the holdout to the claims and uncertainty the team needs.
   Hash/version the corpus and restrict tuning access to development data.
7. Compare each specialty reviewer, the ensemble, and any deterministic
   detector against the independent labels. Report confusion counts, raw
   agreement, per-class precision/recall, false-positive/negative examples,
   and uncertainty. Use kappa as a diagnostic alongside prevalence-aware
   measures, not as a stand-alone acceptance criterion.
8. Test position, length, confidence, and model-family self-preference with
   controlled swaps and paraphrases. Cross-model review is an optional
   calibration design, not a reason to transmit private source to a provider.
   Keep serious minority findings for reproduction instead of majority-voting
   them away.
9. Freeze corpus, rubric, analyzer, and reviewer versions for each calibration
   run. Do not tune on holdout or public claim fixtures; do not claim a 100%
   audit rate from a finite corpus.

### Phase 5 — Feedback, remediation, and rollout

1. Store accept/reject/resolve feedback as minimized, opt-in labels. Do not
   silently learn from private repositories or ship source to a hosted provider.
2. Convert adjudicated failures into development regressions; keep a separate
   holdout set inaccessible to prompt/rule tuning.
3. Let agents propose bounded patches, but rerun the exact reproducer, affected
   proof lanes, full relevant suite, and mutation/holdout checks before marking
   a finding resolved.
4. Start advisory, compare with baseline, then enable blocking only per
   calibrated category and only when evidence-quality hard gates pass.
5. Keep merge, release, deployment, and approval authority outside audit and
   reviewer agents.

## CI acceptance measures

For each supported language and audit category, report:

- coverage completeness and counts for every status;
- held-out TP/FP/FN/TN, precision, recall, and uncertainty;
- clean-case false-positive rate and defect-class recall, including tool-use
  necessity/restraint and known-good controls;
- mutation score with attempted/killed/survived/invalid counts;
- finding reproduction rate and remediation verification rate;
- runtime profiles actually executed and their environment identities;
- p50/p95 duration and resource cost, with paired baseline and no coverage loss;
- actionable-finding completeness and stale/unbound evidence count.

Do not set universal production thresholds from the supplied papers' prose.
First establish a versioned baseline by risk category; then choose explicit
minimums with enough samples to make the stated uncertainty meaningful. Critical
policy/security failures remain hard gates even if aggregate accuracy is high.

## Required completion evidence

Before calling the upgrade operational, require a clean tracked-candidate run,
verified CI receipts bound to its exact commit, successful language-specific
syntax/type checks, the relevant runtime and mutation suites, benchmark
comparison without coverage loss, a sealed holdout report, and a report rendered
from those receipts. Keep the Python source ceiling at 460 throughout; record
the inventory count in CI and reject both count 461 and any attempt to raise
the cap as a workaround.
