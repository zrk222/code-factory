# Integrated accuracy, efficiency and user-value work

Status: active. This is the remaining-work plan for CF, ForgeLine and SpecLine,
following the one-run Astra review. Priority: accuracy, speed, simplicity.
Completed execution history is retained in `docs/evidence/`, not as open tasks.

## Current evidence and acceptance boundaries

- Latest preregistered measurement: Study249, candidate **33 TP /27 FP /0 unclear**, **55.00%** actionable precision on60 decided alerts; nominal Wilson95% **42.49–66.91%**. Baseline33/43=76.74%. The43 common claims show no gain;17 candidate-only ARES alerts are false positives from a repository that timed out on baseline. Two separately blinded same-model AI contexts agreed; no human validation.32/33TPs come from one repository. Full details and limits are in the Study249 result section below.
- Candidate coverage14/15 versus baseline13/15 remains incomplete. The numerical35%/30-decided conditions are reached, but the complete preregistered merge check is false. The owner subsequently explicitly requested commit and merge; GitHub required engineering checks remain enforced. This is not release evidence.
- Study225 (0/49 decided,8unclear), Study210 and earlier exposed development panels remain historical evidence from different cohorts. Study249 is now exposed for future tuning. Never report these cohort differences as a paired precision improvement or label primitive presence as actionable precision.
- PR255 merge bar: **35%+ actionable precision**, at least **30 decided
  candidate alerts**, preregistration, Wilson interval, uncertainty, reviewer
  disclosures and genuine-positive retention, plus all engineering gates.
- Current release threshold, subsequently approved by the human owner: **55% actionable precision** on the sealed Study249 result. The owner validated the reported results and explicitly authorized publishing at55%, with the **next PR targeting80%+**. Required engineering, signed-artifact, cadence and provider gates remain enforced. The study still shows no common-claim gain, incomplete coverage, two AI labelers and concentrated TPs; owner approval does not rewrite those measurements.
- Next-PR target: **80%+** on a new prospectively frozen cohort, at least30 decided candidate alerts, confidence interval, coverage and reviewer disclosure, then90% later. No score is promised by this plan.
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

Historical regression and matrix observations remain in
`docs/evidence/integrated-regressions226.json`,
`docs/evidence/python-matrix230.json` and
`docs/evidence/native-quality235.json`; they do not certify current bytes.
The CLI profile-stub and condition-inventory corrections are committed separately.
At600b42c9 all9 Python CI jobs passed; candidate-quality remained red. The
reviewed native endpoint-copy/reseal and coordinator repair is recorded in
`docs/evidence/native-endpoint246.json`. Its38 focused checks prove bounded
wiring behavior, not a natural precision gain. Run matching CI on the next
committed candidate; do not reuse old green jobs for changed bytes.

Close the remaining native candidate-quality gate. Reproduce only failed cases;
do not rerun passing unit suites. After source integration resolves the current
failures, run one full matching-candidate suite. Retain first failures and exact
platform/job identities. Ruff/C901 success does not satisfy native Forge quality.

## A1 — Deliver source-proven security finding changes

Follow the latest one-run audit `.factory/precision240/astra-detection-audit.md`
and the bounded follow-up `.factory/precision242/ecc-minimal-next-plan.json`, using
existing owners and shared source indexes. The largest exposed family is
44 hardcoded-secret FPs: 29 fixture/local-development, 9 endpoint/sentinel and
6 selector/metadata observations. These counts identify work, not promised removals:

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

Keep selector227/account229 and oversized class-fixture242v3 unadmitted.
Replace the latter's exact-member grammar rather than extending it. Reuse the
existing identity-effect owner for demanded declaration/account/client effects,
source-resolved helper calls and proven disjoint fields. Resolve the selected
model/client/configuration authority; unknown relevant effects retain severity.
A bounded returned-mapping-key query may exclude irrelevant settings keys only;
opaque values and callee effects remain unassessed. It grants no fixture clearance.

First prove one unchanged real fixture declaration through producer, byte-bound
native admission, API, report partition and CLI; then a second independent shape.
Require alpha-renaming, protected-field writes, alias/receiver escapes, unknown
keys, provider mutation, source drift and helper-epoch controls. If selected effects
remain UNKNOWN, stop that expansion and expose the missing edge. Do not build
another per-project resolver or framework-wide lifecycle engine.

## A2 — Wire the same evidence through real product profiles

Normal and full-repository native scans must use the intended captured source,
configuration, import/callable origin and relevant consumer context. A standalone
helper or custom projection is not full CF integration. Version profile changes
separately from detector changes; do not rewrite frozen studies.

Qualify the pushed `workspace-v2` profile and its byte-derived native findings,
dependency edges, atomic partition and exact trusted resume. `isolated-v1` remains
the default until compatibility and complete large-target qualification pass.
The completed narrow wiring records in `docs/evidence/native-workspace-context241.json`
and `docs/evidence/native-byte-dependency241.json` do not establish fixture-family
precision, global closure or readiness to migrate the default profile.

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

The preserved generation13 Nautobot run timed out at 180.391 seconds, with a
920-row checkpoint and no complete JSON report. Generation14 large-target timing
is NOT_RUN. Eager fingerprint construction was removed, but no speed gain was
established. Attribute repeated capture/index/primary/partition costs before
adding another cache; any cache must retain exact source/config/helper identity,
owned copies and independent current-byte native validation.

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


## Study249 measured result and limitations

# Study249: sealed actionable-security measurement

## Result

Two separate blinded `gpt-6.1-sol` high contexts reviewed every claim in the
preregistered 60-unit sample. Both returned the same per-claim decisions.
This is AI-only review, not independent human validation or separate organizations.

| Scanner | TP | FP | Unclear | Decided actionable precision | Wilson 95% |
| --- | ---: | ---: | ---: | ---: | --- |
| Baseline `965d6294` | 33 | 10 | 0 | 76.74% (33/43) | 62.26–86.85% |
| Candidate `e4a46fcb` | 33 | 27 | 0 | **55.00% (33/60)** | **42.49–66.91%** |

Unclear-inclusive candidate rate is also 55.00%. Primitive pattern presence
is 60/60; it is not actionable precision. All 33 sampled baseline TPs are
retained. The candidate exceeds the numerical 35% and 30-decided requirements,
but the complete preregistered merge check is **NOT MET** because coverage is
incomplete. No merge approval or publication claim follows from this report.

## Paired interpretation

- The 43 unchanged exact claims are 33 TP / 10 FP on both scanners: **zero
  measured detection improvement** on that common set.
- Seventeen candidate-only sampled alerts are all false positives from ARES.
  That repository timed out on baseline and finished on candidate. These
  findings do not establish that changed rules introduced new false alarms;
  the baseline has no completed comparable output for that repository.
- The raw descriptive difference is -21.74 percentage points with different
  denominators. It is not a demonstrated rule-quality regression or gain.
- Baseline completed 13/15 repositories; candidate completed 14/15. Bitcart
  remains incomplete (247 audited of 262 Python files). Both input seals pass.
- Thirty-two of the 33 TPs are separate request-to-eval sink locations in one
  repository, FinancialFraudDataGenerator. The unit was preregistered as a
  finding/span, so they remain separate units. This concentration limits
  generalization; the simple Wilson interval does not model repository clusters.
- No target code was executed, imported or installed. No exploitation was run.

## False-positive families in this now-exposed sample

| Family | FP |
| --- | ---: |
| ARES enum/discriminator metadata and synthetic test credentials | 17 |
| Fixed request-body overrides before eval | 5 |
| Operator-selected YAML configuration with explicit FullLoader | 1 |
| Private application-produced pickle cache | 1 |
| Development-only secret selection | 1 |
| Local Docker test TLS verification setting | 1 |
| Public password-hash algorithm configuration in tests | 1 |

These labels may guide development now, but this sample cannot be presented
as a fresh held-out measurement after tuning on them. Do not clear enum or test
findings by name/path alone; prove source roles and retain real credentials.

## Exact evidence

- `score.json`: frozen scorer result, groups, unit labels and input hashes.
- `blinded-packets/manifest.json`: SHA256
  `73ad4bea6f5b04b91cc1e38f599e4c569954be9f7364074bb2b040bc5fd2ddb5`.
- `labels-a.json`: SHA256
  `1fa610199c47450e12634b126bd8806766354691c3f9267179206398f547809b`.
- `labels-b.json`: SHA256
  `eaa6d95c7aa3e4d4c96935cd03baccd19ddefd9be2ee942609b08c2bcba506f0`.
- `candidate-scanner-freeze.json`: exact raw package and canonical Git blobs,
  private candidate commit `e4a46fcb3e243409d420901ec4961f17ae4aab9c`.
- `predictions/{baseline,candidate}/summary.json`: all 15 terminal receipts per
  scanner, original failures preserved without replacement.
- `scoring-addendum.md` and `measurement-tool-freeze.json`: preregistered
  population, sampling, disagreement, denominator and scoring rules.

The exposed Wiki native regression remains separate: its source query qualifies
the fixture, but final source-binding comparison rejects the receipt and retains
the CRITICAL alert. The 52 affected checks and three new allocator controls pass;
they do not override that failed native observation or establish global readiness.


## Subsequent human release decision

The owner stated “AS HUMAN, i VALIDATE THE RESULTS,” then “PUBLISHING AT 55% IS
MET WITH NEXT PR TAKING US TO THE 80+% GOAL.” This accepts the reported55% for
the current publication path. Original packet labels remain AI-produced; no
separate human packet-label submission was received. The owner-requested merge
and publication still require the existing technical and provider checks.
The original pre-registered study result and its unmet full-coverage condition
remain preserved above; the subsequent release decision is a separate authority.
