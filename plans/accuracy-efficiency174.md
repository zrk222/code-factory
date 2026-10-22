# Integrated accuracy, efficiency and user-value work

Status: active. This is the remaining-work plan for CF, ForgeLine and SpecLine,
following the one-run Astra review. Priority: accuracy, speed, simplicity.
Completed execution history is retained in `docs/evidence/`, not as open tasks.

## Current evidence and acceptance boundaries

- Latest fresh measurement: Study225, **0 TP / 49 FP / 8 unclear**, **0%**
  actionable precision on 49 decided alerts, nominal alert-level Wilson95%
  **0–7.27%**. Two separately blinded AI contexts used the same model family;
  this is neither human validation nor cross-model independence. The declared
  full-source profile has coverage/semantic gaps. Preserve all raw outputs,
  original labels, disagreements and gaps. See
  `docs/evidence/fresh-heldout-study225.json`.
- Study225 is now exposed development data. The separate 25% development result
  and Study210's 9.09% use different panels; neither establishes a paired gain
  or regression against Study225. Primitive match rate is a separate observation,
  never actionable precision. Removing FP alerts from a zero-TP set leaves 0%.
- PR255 merge bar: **35%+ actionable precision**, at least **30 decided
  candidate alerts**, preregistration, Wilson interval, uncertainty, reviewer
  disclosures and genuine-positive retention, plus all engineering gates.
- Publication bar: **80%+**, at least 30 decided candidate alerts, preferably
  Wilson lower bound60%+, then90% later. No score is promised by this plan.
- AI labeling is owner-authorized for this pass. Disclose reviewer kind,
  model/prompt separation, packet identity and disagreements. Do not call AI
  review human validation; preserve the original human-plus-AI protocol as unmet.
- Keep genuine positives at justified severity. UNKNOWN is not HOLLOW; a source
  pattern is not necessarily an actionable contextual defect.
- Unchanged architecture caps: **464 Python files / 133 core modules**. Current
  healthy inventory429/133 must remain within caps; no facade files or module
  reclassification to hide growth. Preserve physical file ceilings.
- Standard declared repository scan target: **below180 seconds**, with unchanged
  canonical findings and coverage. Full-suite time is a separate measurement.
- Missing, FAIL or BLOCKED gates prevent completion, merge or release claims.

## A0 — Bind one current candidate and close integration failures

Keep requirement, source/config/helper hashes, execution profiles, observations
and independent ECC review bound to the same candidate. Keep scanner changes,
expectation migrations and mechanical consolidation in separate reviewable
commits. Preserve unrelated edits and frozen studies.

All original24 failed cases passed in the integrated full regression run. That
run recorded8,343passed/6failed/15skipped; its six failures subsequently passed
in a failed-only follow-up. Preserve the timeout and source-generation limits:
`docs/evidence/integrated-regressions226.json`. These are completed observations,
not a claim that current full CI is green.

All nine native CI Python matrix jobs also pass on current source `ffcac796`,
with zero failures/errors in every 8,364-case report; see
`docs/evidence/native-matrix233.json`. The earlier exact-head regression
observations remain in `docs/evidence/python-matrix230.json`.
Close the remaining native candidate-quality gate. Reproduce only failed cases;
do not rerun passing unit suites. After source integration resolves the current
failures, run one full matching-candidate suite. Retain first failures and exact
platform/job identities. Ruff/C901 success does not satisfy native Forge quality.

## A1 — Deliver source-proven security finding changes

Continue the accepted repair order from `.factory/precision215/astra-p0-review.md`
using existing owners and shared source indexes:

1. Credential lifecycle, allocation/enrollment and same-identity local request
   lineage. Cover the coherent account-fixture families before adding unrelated
   proof machinery. Bind actual runner/config/provider generations and every
   credential consumer; inheritance, reflection, mutation and escape must fail
   closed when unresolved.
2. Symbolic credential selectors and route/endpoint metadata. Establish the actual
   consumer role, never infer safety from a name, literal value or project path.
   Reject mixed secret use, provider shadow/rebinding, reflective aliases and
   escaped driver capabilities. Keep modeled external API assumptions explicit.
3. Serialization producer-to-consumer lineage: exact producer, in-memory buffer
   and selected data member. Unknown tags/hooks, external writes, provider
   replacement or ambiguous aliases retain the active finding.

For each admitted family, provide native before/after alert identities, source
coordinates, disposition/severity/evidence changes, complete primitive inventory
and independently recomputed witnesses. Pin paired genuine positives and
adversarial controls. Source drift, helper drift, budget exhaustion or relevant
unknown consumers must revoke provisional clearances. No value/path allowlists,
broad severity demotion or new per-pattern production module tree.

The staged selector227 and account-fixture229 candidates remain unadmitted until
exact frozen bytes, native replay and independent ECC review agree. Rejected
drafts do not contribute wins or measured precision. Report every family outcome,
including retained alerts and unproven cases.

## A2 — Wire the same evidence through real product profiles

Normal and full-repository native scans must use the intended captured source,
configuration, import/callable origin and relevant consumer context. A standalone
helper or custom projection is not full CF integration. Version profile changes
separately from detector changes; do not rewrite frozen studies.

Finish `specs/full-source-coverage211.md` and
`plans/full-source-coverage211.md`: account for every eligible file, capture
read/parse/size failures, and use bounded resumable shared discovery/hash/AST and
dependency indexes. Cross-batch semantic closure must be established explicitly;
complete file accounting alone cannot clear an alert or prove precision.

Preserve source-grounded NORMAL/RETURN/RAISE/UNKNOWN completion semantics and
captured provider effects, cache identity and mutation invalidation. Pin genuine
attrs/Rich dead tests, pass/assertTrue and historical security positives. New
adversarial regressions block admission; do not loosen expectations to pass.

## A3 — Close native quality and keep the code lean

Resolve the unchanged native Forge quality failures in existing owners, then
verify architecture, per-file size, Ruff/format/C901 and public docstrings.
Consolidate duplicated discovery, parsing, binding and proof work; delete truly
redundant implementations after callers and cache identities are migrated.
Do not raise caps or use Ruff complexity as a substitute for native quality.

## A4 — Measure and reduce runtime cost

Measure discovery, hashing, parsing, import closure, effect analysis, rule
execution, cache/revalidation, projection and sealing separately. Optimize the
largest measured phase using shared indexes and bounded caches with integrity
invalidation. Report unprofiled wall time separately from profiler output.

Use frozen inputs and alternating baseline/candidate cold-process and explicit
warm runs. Preserve every run, machine load, median/range and canonical finding,
severity, evidence, unknown and coverage equality. Stop on hidden retries,
missing findings or cache disagreement. The observed full-suite worker imbalance
and repeated distribution hashing are investigation leads, not measured speedups.
Do not weaken production deadlines or treat timeout retries as timing assurance.

## A5 — Freeze and run the next qualification study

After source/profile stabilization, use a non-tuning custodian to preregister an
untouched cohort, rule/maturity scope, rubric, selection seed, semantic alert
identity/deduplication and success criteria. Freeze scanner/dependency/config and
content manifests before predictions or labels; check prior cohorts for leakage.

Run baseline and candidate over the same fixed repository SHAs without executing
target code. Preserve failures without replacement. Hash-order the union of
alerts and label the first60 units, or all if fewer; never replace unclear rows
or stop after a favorable score. Require at least30 decided candidate-emitted
alerts. The35% merge threshold and80% publication threshold remain distinct.

Independent reviewers see the same packets without lane/disposition or each
other's labels. Preserve original submissions; unresolved disagreement stays
unclear under the registered rule. Report per-rule/repository TP/FP/unclear,
actionable precision and Wilson95%, unclear-inclusive rate, primitive match rate,
coverage and duplicates. Report lost baseline TPs/new candidate FPs explicitly.
Fixed positive retention is not recall; alert sampling cannot measure misses.
After unblinding, retire the panel from fresh claims. Do not repeat cohorts until
passing without a separately justified preregistration.

## A6 — Make evidence useful across CF / ForgeLine / SpecLine

Reuse the existing finding/remediation ledger: supported actionable findings,
missing-evidence blockers, coverage, trusted versus experimental scope and one
concrete next action. Preserve raw observations in JSON. Mark long-tail rules
experimental until qualified; never improve the reported score by hiding rows.
Bind actual companion acceptance/execution receipts to current source, config
and obligations. READY/intent digests are not execution evidence or authority.
Missing/stale receipts, changed verifiers and source drift must block promotion.

## Integration, release and near-end commercial work

Before merge: current doctor, independent source review, trusted-positive
retention, architecture/size, Ruff/format/C901, native quality, complete matching
CI and the35% qualifying study must pass. Before publication: meet80% and current
channel/package/install/provider requirements. Demonstrate main remaining green
across subsequent releases; a single local run cannot establish that history.

Commercial work is near the end and **not a merge blocker**: prove precision,
then seek2–3 design partners who choose to block merges on the trusted core;
record actual false alarms, repairs, latency, triage effort and overrides. Use
that evidence to evaluate a focused commercial layer or platform capability
sale. No invented revenue, acquisition or valuation claims. Outreach, contact
sharing, commitments and external-repository changes need separate authorization.
