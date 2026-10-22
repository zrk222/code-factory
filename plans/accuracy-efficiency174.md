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
- The owner authorized AI labeling for the current pass. Two prior blinded
  Codex submissions and Claude's supplied cross-provider review are recorded.
  Claude review is received; its exact bundle identity and blinding are
  self-reported. Report reviewer kind and disagreements.
  Preserve the original human-plus-AI protocol and disclose that its human
  requirement was not met; do not describe AI review as human validation.
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

The exact 53-case CI review is partitioned by source semantics: 19 justified
UNKNOWN expectation corrections, six WEAK expectation corrections, 17 retained
HOLLOW capability controls and 11 unresolved provider/framework controls.
Seven corrections were committed separately in `56d64c2`; the remaining 18
have independent ECC review and a 74-input paired check with identical native
findings. All 31 external regression snippets and attribution/license fields
are preserved; three regression expectations now explicitly require WEAK.
The expectation-only checkpoint has 17 capability controls plus 11 unresolved
controls. Its completed Ubuntu Python 3.11 CI reports 8,291 passed, 28 failed
and 12 skipped at `5fed2656`; see `docs/evidence/oracle-family216.json`.
The separate native nullcontext completion repair restores one existing control
without changing its source or expectation. The 1,558-case audit file now has
1,531 passed and 27 failed, with no new failures: 17 capability controls and
10 provider/framework controls remain. Its 259 scoped tests pass, including
deleted-name, provider-shadow, cache-mutation and bounded-control-flow controls.
The initial unsafe draft and its intermediate AST-only API regression were
rejected and preserved. Full new-head CI remains required. This is test-quality
capability restoration, not security precision gain; see
`docs/evidence/nullcontext-completion217.json`.
Full CI at `0ab81437` then reports 8,316 passed, 28 failed and 12 skipped:
the 27 retained audit cases plus a standalone canonical-provider AST API
regression. Restore that API assumption only when the native source-context
marker is absent; explicit missing/incomplete native captures remain blocked.
All 496 scoped API/oracle checks pass on this correction, with independent ECC
review and no expectation changes. Current-head full CI remains required; see
`docs/evidence/ast-native-completion219.json`.

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

### A6 — Repair after the failed study, then preregister a successor

Study180 has executed and failed: 0 actionable TP, 41 FP and 6 unclear from
47 independently AI-labeled alerts; Wilson 95% interval 0–8.57% per reviewer.
Both blinded AI submissions have those aggregate counts, but disagree on two
specific actionable labels. Consensus keeps disagreements unclear: 0 TP, 40 FP,
7 unclear; Wilson 95% interval 0–8.76%. Seven primitive disagreements also remain
unclear. The scanner and original labels remain frozen. This cohort is now
exposed, so every repair replay is development evidence. Claude's supplied review
has now arrived: 0 actionable TP, 42 FP and 5 unclear; 0% on 42 decided alerts,
Wilson 95% 0–8.38%. It agrees with each prior reviewer on 46/47 actionable
labels. The original two-reviewer consensus and disagreements remain unchanged;
no unregistered majority-vote rule is applied. All 47 local packet source hashes
validate, but Claude's notes supply no reviewed bundle hashes, so exact bundle
identity and blinding remain self-reported. See
`docs/evidence/study180-claude-assessment213.json` and the verbatim review.
The 41 FP / 6 unclear counts belong to the two earlier Codex submissions, not
Claude. The separate submissions are:

| Study180 reviewer | TP | FP | Unclear | S180-006 | S180-036 |
| --- | --- | --- | --- | --- | --- |
| Prior Codex reviewer A | 0 | 41 | 6 | UNCLEAR | FP |
| Prior Codex reviewer B | 0 | 41 | 6 | FP | UNCLEAR |
| Supplied Claude review | 0 | 42 | 5 | FP | FP |

The pending status in `study180-two-ai-assessment204.json` is a historical
snapshot predating Claude's delivery, superseded for review-receipt status by
`study180-claude-assessment213.json`. Its original labels and consensus remain
unchanged; it must not be presented as Claude's submission or current status.
The original human-plus-AI protocol is not satisfied. Only 22 of 24 planned
scans completed; two errored, so declared repository coverage is incomplete.
Development replay at `4465aa3` completes all 12 repositories, including the
original SQL-tokenizer failures, but removes none of the selected 47 alerts.
The next shell-operation candidate removes five agreed false positives from
actionable findings while preserving source-bound primitive observations; the
fixed sample still contains zero actionable TP. This is development cleanup,
not evidence of an improved precision percentage. The final frozen candidate
has independent ECC PASS, 173 passing tests, complete 12-repository replay,
13/13 historical positive controls and healthy architecture (429/133).
Keep the original errors and label disagreements without relabeling away the
failure. Two supplementary preregistered studies have now run on frozen baseline
9886fbc and candidate 07f0bdd. Study209 produced 0 TP / 10 FP / 1 unclear: 0% actionable
precision, Wilson 95% interval 0–27.75%. Study210 produced 1 TP / 10 FP / 22 unclear:
9.09% on 11 decided, Wilson 95% interval 1.62–37.74%. Both scanner versions emitted identical selected alerts;
the paired precision gain is zero. Two blinded AI contexts labeled each panel;
these are not human validation and neither reaches 30 decided. The original A6
qualification below remains unmet. Preserve every capture/exclusion/parse gap.
These panels are now exposed; subsequent label-informed replays are development.

At 917c156, the shared consumer index accounts for all 410 frozen Pyload sources
without exhausting its unchanged numeric limits. Semantic-node accounting omits
only standalone AST marker leaves; full source ASTs and mutation checks remain.
The 8-repository replay leaves all 44 security claims and severities unchanged:
zero measured precision gain. Full semantic closure remains incomplete.

The owner selected full eligible-repository coverage for accuracy and user value.
Complete the separate specs/full-source-coverage211.md and
plans/full-source-coverage211.md profile. The current 8-repository source captures
contain 11,714 Python files; only 2,772 were projected and 2,769 native-discovered in the
earlier panels. Six parse failures remain visible. Consolidate shared inventory,
dependency and analysis indexes; bounded/resumable execution must account for
every eligible file. Missing cross-batch consumer closure cannot clear an alert.
Keep full-profile results separate from the original frozen sample metrics.

The source-coverage implementation is locally qualified: 583/583 eligible Pyload
Python files audited in two batches in 48.19 seconds, no pending files or
parse/read/size errors, 1,332 scoped tests passed, and 13/13 historical positive
controls retained at their original severity. Architecture remains healthy at
429 Python files / 133 core modules. Evidence is recorded in
docs/evidence/full-source-coverage211.json. This completes the bounded source
accounting slice only; semantic consumer closure and actionable precision remain
incomplete. Follow the repair order below, then score the changed outputs
without altering the original frozen panels. The current
comparable actionable result remains 1 TP / 10 FP / 22 unclear (9.09% decided
precision); no gain follows from the file-coverage result.

#### Accepted one-time Astra High repair order (215)

1. Freeze the current module/callable-origin repair with its complete controls
   and any budget failure retained. Then generalize existing fresh allocation,
   credential enrollment and same-identity local-request lineage across the six
   exposed credential fixtures. Require one independently verified native false
   positive reduction before broadening; enumerate all six outcomes.
2. In parallel, bind the four exposed YAML round-trips through the existing
   source index and serialization owners. Start with the exact producer,
   in-memory buffer and data member chain. Require one native false positive
   reduction before adding metadata-selected object members. Unknown custom
   tags/hooks, external writes, provider replacement and ambiguous aliases block.
3. Handle the four settings/header selectors next. Keep the target-specific
   two-header protocol candidate unqualified; stop expanding its global proof.
   Defer shell-template work until an additional admissible source case is
   established before implementing more machinery.

Native admission must preserve the original primitive inventory, source
coordinates and evaluation units. Unsafe or mixed use dominates a benign role;
unknown relevant consumers retain the active finding and severity. Only a
complete, independently recomputed source predicate contradicting the specific
defect claim permits a changed disposition. Final source/helper/profile/budget
validation must revoke provisional changes on drift or exhaustion. Renaming
application symbols must preserve positive controls. Record all old/new claims,
severities, missing/added alerts and retained historical positives; these exposed
replays are development evidence, not new held-out precision. Reuse existing
modules and bounds. After stabilization, run the unchanged fresh qualification
below; the audit itself establishes no precision gain.

Before a successor, resolve the highest-yield families using general source and
consumer models, stabilize the candidate, and preregister a new untouched cohort
under the boundaries below.

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
Then run the separately preregistered successor study on matching candidate bytes.

Publication also requires current channel policy, package/install provenance,
authorization and provider readback. Demonstrate main remaining green across
subsequent releases; this cannot be established by one local test run. Record
time to first justified action and human triage cost before claiming user-value
improvements.

## Current measurements and remaining limits

- Detection integration `4465aa3`: exposed old60 replay removed 23 labeled
  false positives cumulatively, versus 15 before this repair; 37 remain, with no
  previously removed labeled alert returning and no severity changes. All 13
  separate historical positive controls remain at their original severity.
  Same26file PyJWT inventory has45→20 hardcoded-secret alerts:27removed and2new
  unlabelled alerts recorded separately. This all-FP cohort cannot establish
  positive precision or recall. Independent final source review passes within
  the supported provider boundary; see `docs/evidence/local-crypto-operation199.json`.
- Separate exposed development result: 2 TP, 6 FP, 2 unclear; 25% decided,
  Wilson 95% 7.15–59.07%. Do not combine it with the old60 denominator.
- Study180 frozen candidate `c05034e`: 0/41 actionable decided, 6 unclear;
  0% with Wilson 95% 0–8.57%. It was fresh when run, is now exposed, and has
  two independently blinded AI submissions with identical aggregate counts,
  45/47 actionable label agreement and two unresolved disagreements.
  Shell-operation development replay removes five agreed FP rows: first-reviewer
  retained labels are 0 TP / 36 FP / 6 unclear; two-AI consensus is 0 TP / 35 FP /
  7 unclear. Precision remains 0%; this is five fewer actionable false alarms,
  with visible primitive observations, not a generalization score gain.
  All 12 repositories completed and all 13 separate historical TP controls retain
  severity. Independent ECC final review PASS; 173 tests pass. Evidence:
  `docs/evidence/closed-shell-operation207.json`.
  There is no improved fresh-study score yet. See
  `docs/evidence/study180-two-ai-assessment204.json`.
- Supplied Claude review of the same frozen Study180: 0 TP / 42 FP / 5 unclear,
  0% actionable precision on 42 decided alerts (Wilson 95% 0–8.38%). Primitive
  match rate is 39/47 (82.98%), not actionable precision. This does not measure
  the current head or change the separate Study210 result. Prior consensus is
  preserved. Evidence: `docs/evidence/study180-claude-assessment213.json`.
- Current architecture candidate: 429 Python files / 133 core modules; the
  unchanged architecture gate passes after physical module absorption. Evidence:
  `docs/evidence/core-module-target-133-184.json`. Historical full-suite failures
  at `4465aa3` are66failed,8,157passed and12skipped on Ubuntu Python3.11.
  Four raising partial-callback expectation migrations are isolated in
  `1a63c57`; the unawaited partial-callback HOLLOW control is unchanged and still
  fails. Full Ubuntu Python 3.11 CI progressed from 46 failed / 8,273 passed /
  12 skipped at `56d64c2` to 28 failed / 8,291 passed / 12 skipped at `5fed2656`
  in 493.69 seconds. The reductions are the separately reviewed expectation
  corrections, not a security detector gain. The native completion repair's
  local audit-file result is 27 failed / 1,531 passed in 94.35 seconds. Full CI
  at `0ab81437` reports 28 failed / 8,316 passed / 12 skipped in 377.56 seconds:
  27 retained audit cases and one AST-only provider API regression. Its scoped
  repair passes 496 checks; full CI and merge qualification remain failed
  until new-head verification.
  These full-suite and test-file times are separate from the per-repository
  scan target; scoped tests cannot replace the full gates.
- Evaluation-local JWT memoization: an isolated alternating pair on the same
  26-file snapshot measured 16.806s baseline median versus 14.819s candidate
  median (11.82% lower), with equal canonical finding digests and coverage.
  This is a bounded local scan result, not a whole-product speed claim.
- Repository-specific OAuth proof and broad literal-shell severity shortcuts
  were rejected before integration; neither contributes a precision gain.
- Review provenance and packet acceptance are recorded in
  `docs/evidence/astra-plan-integration-174.json`.
