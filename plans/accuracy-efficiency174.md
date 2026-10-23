# Integrated accuracy, efficiency and user-value work

Status: active. This is the remaining-work plan for CF, ForgeLine and SpecLine,
following the one-run Astra review. Priority: accuracy, speed, simplicity.
Completed execution history is retained in `docs/evidence/`, not as open tasks.

## Current evidence and acceptance boundaries

- Latest preregistered measurement: Study249, candidate **33 TP /27 FP /0 unclear**, **55.00%** actionable precision on60 decided alerts; nominal Wilson95% **42.49–66.91%**. Baseline33/43=76.74%. The43 common claims show no gain;17 candidate-only ARES alerts are false positives from a repository that timed out on baseline. Two separately blinded same-model AI contexts agreed; the human owner later validated the reported result, without a separate human packet-label submission.32/33TPs come from one repository. Full details and limits are in the Study249 result section below.
- Candidate coverage14/15 versus baseline13/15 remains incomplete. The numerical35%/30-decided conditions are reached, but the complete preregistered merge check is false. The owner subsequently explicitly requested commit and merge; GitHub required engineering checks remain enforced. This is not release evidence.
- Study225 (0/49 decided,8unclear), Study210 and earlier exposed development panels remain historical evidence from different cohorts. Study249 is now exposed for future tuning. Never report these cohort differences as a paired precision improvement or label primitive presence as actionable precision.
- PR255 merge bar: **35%+ actionable precision**, at least **30 decided
  candidate alerts**, preregistration, Wilson interval, uncertainty, reviewer
  disclosures and genuine-positive retention, plus all engineering gates.
- Current merge decision: the human owner accepts the sealed Study249 **55% actionable precision** result for PR #255, subject to the required technical checks. **Publication is on hold** under the later instruction below until the next precision PR, requested as PR #256, is completed with higher measured scores; its target is **80%+**. Original score, coverage limits and label provenance remain unchanged.
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
- Thirty-two of the 33 TPs come from FinancialFraudDataGenerator: 31 dynamic-
  execution findings and one hardcoded-secret finding. The remaining TP is a
  hardcoded-secret finding in ihatemoney. The unit was preregistered as a
  finding/span, so they remain separate units. This concentration limits
  generalization; the simple Wilson interval does not model repository clusters.
- No target code was executed, imported or installed. No exploitation was run.

## False-positive families in this now-exposed sample

| Family | FP |
| --- | ---: |
| ARES enum/discriminator metadata and synthetic test credentials | 17 |
| Fixed request-body overrides before eval | 4 |
| Database JSON value evaluated as code | 1 |
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


## Superseding publication hold and next precision PR

The owner subsequently instructed: “AFTER COMPLETED MERGE DO NOT YET PUBLISH PR
255 UNTIL WE FINISH PR 256 WITH THE HIGHER PRECION SCORES.” This supersedes the
earlier permission to publish at 55%. Continue required-check repairs and merge
PR #255 when green, then hold its publication. No publish dispatch, public
release, or package upload is authorized by the earlier 55% decision while the
hold applies. The named PR #256 is planned and was not yet present when checked.

A one-time Astra High senior security precision engineer review will produce
the implementation plan for the next PR's 80%+ focus. It must prioritize
actionable defects, retain known TPs, close coverage gaps, and use a new
prospectively frozen evaluation after exposed-data development. The report
and the target do not constitute a measured gain or release approval.


## Study249 narrative correction (labels and score unchanged)

The one-time Astra source audit independently recounted exact packet IDs.
FinancialFraud's 32 TPs are 31 dynamic-execution and one hardcoded-secret
finding, rather than 32 request-to-eval sinks. Its five dynamic-execution FPs
are four dominating overwrite/decode cases (F249-010,025,035,043) and one
database JSON case (F249-036). This corrects the narrative above; original
score, packet labels, manifest hashes and frozen private RESULTS.md remain
unchanged. The machine-readable source audit records the exact TP IDs.

## Next precision PR: one-time Astra High senior security plan

The following is the source audit, with the review clarification that test
intent registration precedes test edits and the 99.85% candidate-quality gate
is enforced at qualification/merge. The proposed fresh-study breadth and
adjudication gates apply to the follow-up plan; they do not add new merge
conditions to PR #255. Publication remains on hold.

# PR256 security precision: source-grounded implementation plan

Status: **SOURCE REVIEW COMPLETE; IMPLEMENTATION AND NEW MEASUREMENT NOT RUN.** This is the one-time Astra senior security precision audit. Only this report and its JSON companion are authored by this audit. The live checkout and its four dirty files were preserved.

## Decision

Keep PR255's merge decision separate from publication. Merge only under the owner's required-CI authorization; publication remains held. PR256 is the owner's name for the next precision PR, not a verified existing PR number. Begin implementation on a separate branch from the exact merged PR255 commit, preserving its working improvements. Rebind this plan's hashes after that merge; do not base detection changes on the dirty live HEAD965 checkout. The source reviewed here is `.factory/precision251/candidate`, derived from PR255 head14871652 with private mock dedup changes; the JSON records exact inspected file hashes.

Implement the three P0 items below in existing modules. Do not add proof modules or expand architecture caps (464 Python files,133 core modules). Favor one shared value/use summary over a new exemption family for each repository. Reuse the current primitive-observation partition and source-binding validators. That partition must consume source-proved roles, never study labels, filenames, symbol spelling or a post-scan score filter.

## Evidence and corrections

The sealed Study249 result is candidate33TP/27FP/0UNCLEAR,60decided,55.00%, Wilson95 42.49–66.91%; baseline33TP/10FP/0UNCLEAR,43decided,76.744%, Wilson95 62.26–86.85%. All43 common exact claims have identical labels: zero paired detection gain. The17 candidate-only ARES FPs came from a baseline timeout; they do not prove a rule regression. Two blinded contexts of the same model agreed60/60. Human owner acceptance of these results is not a third independent labeling pass.

Two summaries require correction before reuse:

- Five FinancialFraud dynamic-execution FPs are **four overwritten request bodies** (010,025,035,043) and **one database JSON value** (036). Treat036 separately.
- FinancialFraud contributes31 dynamic-execution TPs plus1 hardcoded-secret TP; ihatemoney contributes1 hardcoded-secret TP. Thus32/33TP still come from one repository, but they are not32 request-to-eval sinks.

Study249 is now exposed development data. Its frozen scores remain historical; reruns after these fixes are development regressions only. Candidate coverage was14/15 repositories; Bitcart had15 Python3.12-syntax files unsupported by the3.11 scanner host. Baseline completed13/15. Neither percentage establishes a broad complete-coverage release claim.

## P0-1: recognize public metadata through resolved use, not spelling

**Opportunity:8 labeled FPs, not a predicted removal.** Packets004,007,014,019,032,046,054,059. Examples: `ares/core/token_sessions.py:39–40` event kinds; `ares/modules/descriptors.py:75–76,146,153` type/handle/environment selectors; `ares/credential/vault.py:62` credential-category discriminator; `ares/normalize/artifacts.py:58` artifact type.

**Verified root cause.** `review_audits.py:1515–1527` promotes a string assignment to CRITICAL from `_SECRET_ASSIGNMENT` matching its identifier. `provenance.py:572–596` admits a symbolic candidate only when literal value exactly equals member spelling and bases exactly resolve to `[str, enum.Enum]`. ARES uses lowercase serialized values for uppercase enum members, so `_LiteralConsumers._class_members` (`runtime_audit_integrity.py:1872`) never indexes them as candidates. Broadening that syntax gate alone is insufficient: `witnesses:3345` still requires every relevant reference to be a proven public consumer, and any incomplete graph can discard witnesses (`provenance.py:327–395`).

**Smallest safe change.** Let a resolved enum declaration with an immutable scalar value enter the existing analysis independent of case/spelling; this is candidacy, not exemption. Track its member identity and all reads through imports/reexports, `.value`, containers and known source constructors. Extend the current use classifier with source-backed discriminator effects: comparisons, type/schema selection, public serialization and indexing. Record exact assignment/use spans and source hashes. A member passed as a password, authorization value, signing key, account enrollment input, arbitrary callback or unknown consumer stays an alert. Publicly exposed credentials can still be security defects; public visibility alone never proves a noncredential role.

Use the existing `_LiteralConsumers` index, provider mutation checks and memoization. If ARES exceeds supported consumer shapes, emit the first unresolved edge/cause; do not relax the whole graph or add ARES-specific code. Any attempt to localize graph incompleteness must still prove complete references to the selected binding; a global inventory or reflective-reference gap cannot be ignored.

**Acceptance.** Paired native scans retain every33 TP claim at original priority. For the8 named FPs, require actual source-bound metadata witnesses, not merely fewer findings. Negative controls: enum value used for JWT signing/auth, alias imported into another module, `.value` passed to a sink, provider rebinding, custom equality, mutable container escape, hidden/oversized consumer, stale receipt and exhaustion. Existing anchors: `test_public_enum_scalar_json_retains_signing_consumer`, `test_public_enum_json_retains_unproven_consumers`, `test_public_enum_native_incomplete_source_denies_admission`, and cold/warm invalidation checks in `tests/test_runtime_audit_integrity.py`.

## P0-2: propagate the last immutable value into eval

**Opportunity:4 labeled FPs.** Packets010,025,035,043. In gambling `other_views.py:18–21`, the request body is read, overwritten unconditionally with fixed bytes, decoded, then evaluated. The input reaching eval is the replacement; the preceding request read must not remain the input's provenance.

**Verified root cause.** `runtime_audit_integrity._fixed_literal_call:326` requires the call argument itself to be a string AST constant. `finite_capture.finite_literal_eval_input_witness:980` supports a specific finite comprehension domain, not arbitrary local reaching assignments. `primitive_observation_binding.fixed_program_witness:1247` tries these existing witnesses; neither matches the overwrite/decode chain. The fallback `review_audits._dynamic_execution_finding:1391` emits HIGH.

**Smallest safe change.** Extend the existing witness path with a bounded, ordered local reaching-value summary: UNRESOLVED, external input, immutable literal bytes/string, or conflict. Strong-update a simple local name only on a dominating unconditional assignment. Resolve aliases and builtin bytes.decode only for proven bytes receivers and fixed supported encoding; never call arbitrary target methods. Use the existing literal-program AST whitelist to confirm that the resulting text contains inert data, not calls, attributes or executable operations. Bind the witness to the original sink and the full def-use slice, including overwrite and decode spans. Keep the raw primitive observation visible through the existing validated partition.

Do not implement general taint/CFG infrastructure for this first slice. Reuse `review_integrity.remember_direct_constant_assignment:2398` invariants where appropriate, but do not globally change constant folding or synthesize a new AST without binding it to the real source. At conditionals, exception paths, loops, nonlocal/global writes, callbacks or reflection, conservatively reject the witness unless the same immutable value reaches the sink on every path. Reject bytes subclasses, unknown encodings, mutated builtins and shadowed eval.

**Acceptance.** All4 named native findings become validated inert-input observations; all31 FinancialFraud dynamic-execution TPs remain alerts. Mutation controls remove the overwrite, move it into one branch, evaluate before overwrite, restore request input, inject an executable fixed program, alter decode receiver/encoding, rebind eval, and invalidate a recorded source hash. Unknown control flow remains HIGH/unfinished proof; no blanket `eval(name)` downgrade.

**Explicit exclusion.** Packet036 is database-origin `consumption_range` at `StoreService.py:273`. Its label cites a JSON column and JSON-encoding writer. It is not covered by the overwrite fix. Do not assume all database values are safe; a future separate proof must bind all writers, schema/version, allowed data domain and absence of alternate writers. Until then retain its alert and document the exposed FP.

## P0-3: distinguish fixture plaintext from authority-bearing credentials

**Opportunity:9 labeled FPs.** Packets017,020,022,029,034,042,047,049,058. These include FakeForm dependency overrides, encryption/plaintext roundtrips, temporary database storage, ephemeral vault data, and an in-process integration signing fixture. They do not all share one mock shape.

**Verified root cause.** The same lexical secret rule emits CRITICAL. Existing `credential_role_identity_effects.module_fixture_credential_evidence:2051` demands Django settings/model plus one enrollment creator and login consumers (`_fixture_role_rows:1988`, `_fixture_role_pair:2017`). ARES uses FastAPI/local vault flows. `mock_fixture_provenance.closed_jwt_test_literal:3785` and `_jwt_crypto_operation_witness:3384` cover bounded JWT crypto, not generic local plaintext storage. Existing tests or naming conventions are not evidence of isolation.

**Smallest safe change.** Reuse these identity/effect and fixture-binding paths, extending the shared role result to carry: material role (payload versus authority), origin/owner, complete consumer uses, persistence/transport escape, and explicit unknown reasons. Start with easier local plaintext roundtrip cases034,047,049,058. Resolve actual source methods, fixture providers and constructors; their names alone do not imply inert behavior. Next prove017/029 dependency override and mocked authentication binding. Handle020/042 only with the temporary database lifetime and consumer graph closed. Handle022 last because a signing key really grants authority: require in-process client binding, test-owned settings, isolated storage, restoration/lifetime evidence and no production import/export or transport escape. Failure to prove any of these leaves the alert.

A function-scoped constant, test filename, `TestClient` spelling, equality assertion, ephemeral-looking key or test comment is never sufficient. An assertion comparing a value after a real network send does not close the escape. Avoid expanding a JWT-specific function into a giant unrelated dispatcher: reuse its supported effect summaries in existing identity-effects code and keep the publisher/validator in `primitive_observation_binding`.

**Acceptance.** Native before/after findings for all9 packets are individually explained; incomplete ones remain alerts. Retain the two Study249 hardcoded-secret TPs, existing real-secret controls and every33TP overall. Mutation controls send a fixture value to a real HTTP authentication sink, export it to application settings, make the client transport unknown, persist to a configurable external DB, replace the fixture provider, add a callback consumer, bypass env restoration or change source bytes. Existing anchors include `test_real_credential_positive_is_retained_at_original_priority`, `test_omitted_oversized_auth_consumer_keeps_original_credential_alert`, and JWT/source-binding negative controls.

## Do not spend the first iteration on the remaining six

Retain and report003 FullLoader operator configuration,018 private pickle cache,036 database JSON eval,039 development secret,052 Docker-test TLS override,060 password-hash algorithm identifier. These are labeled FPs in this snapshot; robust general exemptions need different trust/configuration facts. In particular, FullLoader is not uniformly equivalent to SafeLoader across dependency versions, a local file may have an attacker-controlled writer, and a dev module can be selected in deployment. Do not turn uncertain environmental assumptions into silent passes. Packet060 is a useful later extension of the value-role distinction (algorithm selector versus password), without an identifier allowlist.

## Exposed development acceptance and arithmetic

Freeze the prechange candidate and compare the same60 packet identities plus a complete repository scan before and after each P0 change. Archive TP/FP/UNCLEAR, native alert/observation membership, retained original severities, coverage and timing per family. Do not score only the three favorable families. Every newly introduced alert needs labeling; include an all-alert check so gains are not hidden by a fixed60 subset. Require33/33 original TP retention, no new unknown/coverage failures, validated source witnesses for every removed FP, and unchanged protected negative controls. These are exposed regression results, never fresh accuracy claims.

Conditional arithmetic only: with33TP retained, at least19 of27FP must be legitimately resolved to exceed80% (33/41=80.49%). Resolving the entire21-FP opportunity would leave33TP/6FP,84.62%. None of those removals has been implemented or measured. Metadata+overwrite alone is12FP and only68.75% (33/48). This is why changing enum casing alone cannot honestly promise80%.

Before editing tests, register the requested test intent through the existing CF plan/assembly/workflow-QA route. Require the candidate-quality 99.85% attribution gate at candidate qualification and merge; the parent owns that check. Registering intent precedes test implementation, while the gate is evaluated after those tests exist. The earlier count of 182 referred to missing test-intent units, not a numbered workflow. Bind candidate hashes and exact command receipts in the existing route. No new proof subsystem is needed. Run the focused named test files, protected controls and complete exposed native replay on the implementation branch; rebuild hashes before later verification.

## Fresh release protocol: freeze first, then run once

1. After development gates pass, freeze candidate code/package, baseline package, interpreter, dependencies, scanner options, all rule severities, labeling rubric, unit/dedup policy, sampling seed, cohort and reserve selection, limits and scorer before predictions or labels. Study249 and previously inspected repositories cannot be the new held-out cohort. Use a curator/context that has not tuned the detector to select by public project characteristics, not predicted alerts. Include at least20 independently maintained repositories across web/API, CLI/data, libraries, and infrastructure/security tools; include supported syntax/version strata and tests. Do not merely collect intentionally vulnerable copies of one application.
2. Prefer a census of all baseline/candidate alert union. If labeling must be sampled, preregister per-repository/rule inclusion probabilities, deterministic selection and weighted aggregate estimation; publish all raw alert counts. Do not cap or remove a high-volume repository after seeing predictions. Any fixed sample is explicitly a sample estimate; publish repository/rule macro and clustering limits alongside it. A maximum cohort/reserve is fixed upfront; insufficient alerts/diversity fails feasibility rather than allowing score-driven expansion.
3. Run both sealed scanners on the same source bytes and compatible interpreter. Target code is parsed only, never imported/executed/installed. Retain180seconds/repository and2workers from Study249 as the initial declared runtime budget; candidate must complete every selected repository, with discovered=attempted=audited and zero parser/unreadable/oversize gaps. Fix/declare Python3.12 support before freeze; do not lower the supported cohort after observing failures. Preserve both timeout receipts. A baseline timeout makes that repository's pairing unavailable, not zero baseline alerts.
4. Blind the two labelers to scanner membership and improvement goals. Freeze separate prompts/model identities. Label actionable defect, primitive presence and UNCLEAR separately using captured source context and exploit/trust-boundary reasoning. Require at least90% raw actionable-label agreement; report confusion table and Cohen kappa with prevalence caveats. Human reviewer adjudicates disagreements and audits claimed TPs plus resolved security exceptions. If both labelers share a model, say so; never call owner score acceptance independent ground truth. Freeze labels before unblinding.
5. Minimum numerical gates: at least30 decided candidate alerts; TP/(TP+FP)>=80%; also TP/(TP+FP+UNCLEAR)>=80% with UNCLEAR<=5%; retain100% of adjudicated baseline TPs on completed paired sources. Report all lost/new/common claim counts and reasons. A reported80% point estimate must include Wilson95 bounds and must not imply an80% lower confidence bound. If the publication claim is 'at least80% with95% confidence', require the lower bound itself>=80%, which30decided may not establish.
6. Breadth gates for a broad multi-repository claim: TPs from at least5 repositories and3 rule families, largest repository<=40% of TPs, repository-macro and rule-macro precision each>=80% over defined nonempty strata. Report every stratum, empty denominators, largest-cluster share, and repository-cluster uncertainty in addition to ordinary Wilson. If the preregistered cohort fails breadth, report the bounded result and keep publication held; do not relabel, prune or replace offending repositories. These thresholds are proposed preregistration gates, not observed performance.
7. Precision is not recall. Report100% observed baseline-TP retention separately from recall. Add a sealed reference set of independently established defects across the selected rule families, plus preregistered review of scanner-negative source/sink candidates. Report sensitivity only against that known set and any estimated-negative sampling method; do not claim full repository recall from alert labels or synthetic mutations. Require all relevant known defects retained and no decrease in paired sensitivity. Publish any unsupported strata.
8. Measure cold per-repository runtime, total wall time, median/p95 and peak memory on the same host/profile; keep cache policy and worker count fixed. Proposed speed gate: median andp95<=1.20x matched complete baseline, no180second timeouts, and no coverage loss. Ratios are unavailable for failed baseline runs; report absolute timing there. Use existing indexes and content-hash caches; bound effect work and retain UNKNOWN on exhaustion. Do not raise work budgets until timing evidence justifies it.
9. Freeze/seal results and adjudication, run required CI and native evidence checks, then present the exact score/coverage/latency/retention packet to the owner. Any tuning after fresh labels are exposed converts that cohort to development data; a new claim requires a newly frozen untouched cohort. No publication follows automatically from this audit or from PR255 merge.

## Verification boundary

`factory doctor --strict --json` exited0 with installation/workflow/provenance OK; `factory plan --help` was inspected to route this documentation-only plan. Source reads, packet/label census and SHA256 binding were performed. No target code, scanner, tests or exploit was executed for this audit. Source hashes and33 exact TP IDs are in `astra-action-plan.json`. The next implementation's native closure success, precision, recall, latency and architecture health remain NOT_RUN. The ECC security-review skill informed credential/trust-boundary checks; ECC benchmark-methodology was inspected and its competitor-brand rubric rejected as inapplicable to detector scoring.

## Separate memo-freshness advisory

The parent reports one failing direct-contract test (13 passing) in `.factory/precision251/targeted/getter-behavior/tests.log`: warming `credential_role_method_use_getter_audit.snapshot_candidates`, then changing the source inventory digest, still returns cached candidates; `SourceSnapshotIndex.validate` reportedly caches by path. This audit did not reproduce the test. Production ClassChainMemo/fresh-byte receipt binding may reject the stale result, so this is an advisory cache-validity gap, not an established actionable security bypass. Trace that native effect first; if confirmed, reuse the existing source generation/content-hash validity key and invalidate the stale entry in existing modules. Keep this separate from the measured false-positive work and retain the final independent source binder.
