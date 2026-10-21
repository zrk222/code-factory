# Integrated accuracy, efficiency and user-value work

Status: active; authorized by the user on 2026-10-21 after the one-run Astra
high review. This extends the existing CF/ForgeLine/SpecLine goal. It does not
replace outstanding delivery, integration, release or stability requirements.
Only remaining work is listed below. Order: accuracy, speed, simplicity.

## Acceptance boundaries

- Publication target: at least 80% actionable precision on a fresh preregistered
  sample with at least 30 decided candidate alerts. Report the Wilson 95%
  interval, primitive match rate, unclear count and positive retention separately.
  The later target remains 90%; no score is promised by this plan.
- Use an actual human label submission and a separate blinded AI label set.
  Preserve disagreements. AI review of implementation is not human labeling.
- Keep all genuine positives at their justified severity. UNKNOWN is not HOLLOW;
  a primitive observation is not a proven actionable defect.
- Architecture ceilings are 464 Python files and 133 core modules, following
  the owner's subsequent instruction to reduce the module target to 133. Do not
  increase caps, reclassify modules to hide growth, or leave facade files.
- Repository scan target is below 180 seconds on the declared standard profile,
  with unchanged coverage and canonical findings. Full-suite time is separate.
- Missing, FAIL or BLOCKED checks prevent a completion, merge or release claim.

## Remaining execution packets

### A0 — Preserve one current candidate

Keep a ledger of requirement, candidate hashes, execution profile, observation
and independent review. Rebind downstream evidence after source changes.
Separate scanner changes from expectation migrations and mechanical moves.
Revalidate both raw bytes and Git content; explain line-ending differences.

### A1 — Finish semantic family adjudication

Use the preserved full-suite failure ledger. Classify each family as a product
defect, an invalid old expectation, or unresolved. Retain original failures and
the source-grounded reason for any expectation migration. No bulk UNKNOWN edit.
Keep pass/assertTrue, attrs' genuine docstring-only case, the three Rich
SHADOWED cases and historical security positives pinned separately.

### A2/A3 — Repair shared operation and completion models

Existing owners: `factoryline/context_efficiency.py`,
`factoryline/review_integrity.py`, `factoryline/test_oracle_misuse.py`, and
`factoryline/type_intent_hollow.py`. Reuse captured source/provenance owners.

Establish the actual lexical binding and generation, relevant initializer and
provider effects, selected operation, evaluated arguments and bound parameters.
Serialize every prerequisite needed to reproduce a cached proof. Extend the
existing NORMAL/RETURN/RAISE/UNKNOWN transfer; distinguish coroutine creation
from execution and known raises from inert completion. Preserve analysis limits.

Start with captured async completion (26 historical failures), exception flow
(12), and vacuity/local truth (9): 47 recorded failures, not a production
false-positive distribution. One shared mechanism should serve multiple cases.
Rejected async164 and getter170 shortcuts stay excluded.

Accept only with paired genuine positives and adversarial controls for arity,
eager raises, shadowing, constructors, imports, fixtures, decorators and source
drift; require cold/first-hit/warm equality and helper mutation invalidation.
Any unsafe HOLLOW counterexample blocks admission. Do not build a new interpreter
or per-pattern proof-module tree.

### A4 — Close native quality and preserve the architecture budget

The physical consolidation target is met: 429 Python files and 133 core modules;
the unchanged architecture health gate passes. Keep those ceilings and all
per-file limits intact as accuracy work proceeds. Refactor measured native Forge
hotspots in existing owners; both its unchanged quality gate and Ruff/C901 must
pass. Do not equate those metrics or treat architecture PASS as full CI approval.

### A5 — Measure and reduce runtime cost

Instrument existing discovery, hashing, parsing, import closure, effect-model,
rule, cache/revalidation, projection and sealing phases. Measure unprofiled wall
time separately from profiler output. Optimize the largest measured phase.

Use frozen inputs and alternating baseline/candidate cold-process and explicit
warm-cache runs; retain every run and report median/range and machine load.
Compare canonical findings, severities, reasons, evidence, unknowns and coverage.
Stop on missing findings, cache disagreement, hidden retries or coverage loss.

For slow subprocess tests, record bootstrap/readiness, collection, execution and
cleanup. Compare controlled worker counts before changing scheduling. Preserve
production deadlines and the complete test inventory; no timeout-to-PASS retry.

### A6 — Execute the fresh precision study

Use a non-tuning evaluation custodian. Freeze the rule/maturity scope, labeling
rubric and acceptance thresholds before viewing outputs: at least 30 decided
candidate alerts, at least 80% actionable precision with a Wilson 95% lower
bound of at least 60%, no lost trusted positives and complete declared coverage.
Primitive TP means the observation is present; actionable TP requires a
supported contextual defect and justified repair; FP requires sufficient
contradicting context; insufficient context or unresolved disagreement is unclear.

Before scanning, publish immutable scanner/dependency/config manifests and a
selection frame, seed and exclusions for 12 previously unexposed Python
application repositories at fixed commits. Check all prior cohorts/tuning data
for contamination. If the fresh frame is insufficient, report that explicitly.

Scan the frozen baseline and final candidate without target execution. Preserve
all errors, missing coverage and raw alerts. Retain failed repositories without
replacement; no posthoc exclusion may improve the result. Use a preregistered semantic alert
identity and deduplication rule. Hash-order the union of both lanes and label
the first 60 units (or every unit if fewer). Do not replace unclear items or
stop labeling after reaching a favorable score. At least 30 candidate-emitted
alerts must receive decided labels; otherwise qualification is insufficient.

The human and independent AI label the same packets without lane, disposition
or each other's labels. Preserve original labels and adjudication reasons.
Report per-rule/repository TP, FP, unclear, actionable precision with Wilson
interval, unclear-inclusive rate, primitive match rate, coverage and duplicate
counts. Show disappeared baseline TPs and new candidate FPs. Fixed historical
positive retention is a separate table, not recall. Alert sampling alone cannot
measure false negatives. After unblinding, retire the cohort from fresh claims.
This packet permits one 60-unit study, not repeated cohorts until passing.
Subsequent repairs prompted by the labels require a separately preregistered
fresh cohort and remain development retests on this exposed sample.

### A7 — Make results useful across CF/ForgeLine/SpecLine

Reuse the existing finding/remediation ledger. Present supported actionable
findings first, explicit missing-evidence blockers next, and a concise coverage
and trusted/experimental summary with one concrete next action per item. Keep
all raw observations available in JSON; never improve the metric by hiding them.

Bind actual companion acceptance/execution receipts to the current source,
configuration and obligations. A READY state or intent digest alone is not
execution evidence or human authorization. Test missing/stale receipts, changed
gates/verifiers, incomplete observations and source drift during promotion.

## Integration and release closure

After the integrated candidate freezes: strict doctor, scoped independent
reviews, all trusted positives, architecture ceilings, Ruff/format/C901,
public-docstring checks, native Forge quality, and one complete current full
suite must pass. Preserve contended runtime failures and reconcile each family.
Then run the sealed study on matching candidate bytes.

Publication also requires current channel policy, package/install provenance,
authorization and provider readback. Demonstrate main remaining green across
subsequent releases; this cannot be established by one local test run. Record
time to first justified action and human triage cost before claiming user-value
improvements.

## Evidence baseline, not a new result

- Accepted integration: `4184a9b`; scoped family migration: `1df111a`.
- Development-only actionable result: 2 TP, 6 FP, 2 unclear; 25% decided,
  Wilson 95% 7.15–59.07%. Fresh held-out precision remains unmeasured.
- Current architecture candidate: 429 Python files / 133 core modules; the
  unchanged architecture gate passes after physical module absorption. Evidence:
  `docs/evidence/core-module-target-133-184.json`. Historical full-suite failures
  still need a current integrated rerun; scoped passes do not subtract from them.
- One recorded full social-core scan took 152.636 process seconds. No paired
  speed gain is established.
- Review provenance and packet acceptance are recorded in
  `docs/evidence/astra-plan-integration-174.json`.
