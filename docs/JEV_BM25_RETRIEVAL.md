# Jev + BM25/BM25F rule retrieval

Code Factory now uses a two-stage, optional retrieval/classification path for
large rule inventories:

1. **BM25/BM25F retrieves locally.** `factory.search_audit_rules` defaults to
   deterministic BM25F ranking. `ranking: "bm25"` uses a single-field score;
   `ranking: "lexical"` preserves the legacy substring search. BM25F gives
   higher weight to the rule name and rejection code than to descriptive text,
   so an agent sees the most actionable conditions first.
2. **Jev may classify the bounded candidates.** The result contains a
   secret-free `jevHandoff` with candidate rule IDs and a context hash. A host
   may pass that handoff to an injected Jev transport and validate the typed
   result with `factoryline.jev_classifier.classify_retrieval`.
   `fuse_advisory_scores` can blend per-rule Jev scores with local relevance;
   CF keeps local BM25/BM25F dominant and preserves local order when Jev
   scores are missing or invalid.
3. **CF remains the authority.** Jev labels are advisory routing hints such as
   `RUN_LANE`, `TARGETED_REPAIR`, or `HUMAN_REVIEW`. Invalid, stale, low-quality,
   or unavailable Jev output fails closed to `HUMAN_REVIEW`. It cannot execute
   a lane, alter a threshold, approve a release, merge, publish, or grant
   credentials.

The default path is offline and provider-free. This preserves local operation,
keeps rule discovery explainable, and lets teams measure Jev against their own
defect corpus before enabling it. Required measurements include precision,
recall, calibration, false-negative rate, latency, and fallback rate; no
provider speed or cost claim is inferred from the adapter.

## Developer value roadmap

These stages are planned integrations. The evaluation runner and optional
advisory grading are implemented separately; they do not establish that these
developer workflows are complete or calibrated.

| Order | Workflow | Evidence supplied | Developer output | Acceptance evidence |
| --- | --- | --- | --- | --- |
| 1 | Finding adjudication | Finding, source location, resolved helpers/callers, analyzer version and negative controls | Supported finding, suspected false positive, or unresolved; exact next check | Frozen external-repository cases, per-category precision/recall and false-positive rates; no loss of known-defect detection |
| 2 | Requirement-to-behavior review | Explicit requirement, changed source, execution traces and expected outcomes | Missing behavior or oracle, with a reproducible validation action | Paired satisfied/violated requirements, runtime controls, ambiguous-requirement abstentions |
| 3 | Repair comparison | Original failure, patch, before/after receipts and affected contracts | Remaining defect or introduced risk, with repair/recheck steps | Genuine repairs versus incomplete repairs, regression controls, candidate-drift rejection |
| 4 | Change-impact review | Diff, dependency/caller graph and interface contracts | Affected consumers and missing regression evidence | Independently labelled cross-module changes; measured missed-impact and irrelevant-action rates |
| 5 | Actionable criterion grading | Separate correctness, maintainability and requirement criteria with sufficient evidence | Criterion pass/fail/unresolved and remediation; deterministic score aggregation | Label-blind scoring, unresolved-score refusal, frozen holdout calibration and repeated non-regression |

### Shared operating contract

- Keep counts, hashes, coverage arithmetic, dependency checks and release gates
  deterministic. Jev interprets evidence where semantic review adds value.
- Verify candidate, source, tool, policy and evidence bindings in the host before
  admitting a judgment. Repository comments and model output are untrusted data.
- Each criterion states one observable violation, minimum evidence, pass/fail
  examples and scope. Source evidence cannot establish runtime isolation.
- Return location, evidence references, uncertainty and a concrete next action.
  Jev never suppresses a scanner finding or executes a repair automatically.
- Grade only admitted decisions. Unresolved criteria keep the numeric grade null;
  score intervals are possible bounds, not achieved grades. Critical failures
  retain their existing blocking policy.
- Cache advisory results only against matching source, evidence, rubric, model
  and policy identities, with expiry and invalidation. A model identifier does
  not prove immutable weights. Stale results cannot clear findings.
- Use explicit opt-in, bounded requests, a spend ceiling and redacted minimal
  evidence. Record actual reported cost, latency, abstentions and fallback rate.

### Validation and rollout

Freeze development and independently adjudicated holdout sets before tuning.
Include real helper/mixin layouts, swallowed failures, incomplete repairs,
missing evidence, source drift and repository prompt injection. Test evidence
order and verbosity changes. Publish counts and confidence intervals by category;
do not treat attribution or model confidence as detection accuracy.

Start in shadow mode, retain disagreements, then enable optional advisory
recommendations only for categories that meet a reviewed acceptance policy.
Measure review time and accepted actionable recommendations against the existing
CF baseline. Broader grading or gate influence requires separate calibration,
non-regression evidence and explicit policy admission; it is not automatic.

### Live trial checkpoint: 2026-10-09

Twenty-four Vercel Gateway Jev calls completed across paired source controls,
report-consistency controls, actual CLI/CodeQL receipts, two prompt-injection
controls and two grading controls. All remained unresolved at the unchanged
evidence threshold of 0.9. The first 22 calls reported a combined cost of
US$0.001075032; the two grading calls reported US$0.000072408. These small
development trials do not measure independent production accuracy. They support
keeping Jev advisory while improving evidence packaging and validating the
framework. The runner records both model probabilities and abstentions; neither
a directionally plausible answer nor successful HTTP transport is an admitted
grade.

## Scope gate

Run the feature-scoped gate, which audits only the two implementation modules:

```powershell
forge qa jev-bm25-retrieval-v1 --ssat specs/jev-bm25-retrieval-v1.ssat.yaml --root . --strict
```

Do not substitute `--repo-wide` for this slice. That inventory scope includes
unrelated generated wheels and TypeScript/TSX products, so a Python-only audit
would report parser and coverage failures outside this feature.


## Security actionability through Vercel AI Gateway

`factory audit actionability --root . --cases cases.json --out review.json`
uses the evaluator shipped in the CF wheel. It requires Node.js 18+ on PATH;
no JavaScript package installation or separate provider client is needed.
The default is offline (`NOT_RUN`), not a model assessment. For a live review,
configure `AI_GATEWAY_API_KEY` in the invoking process and add
`--live --budget-policy budget.json`. Never put a key in the case JSON, argv,
repository, or CF configuration. Each user supplies their own gateway access.

The fixed endpoint is `https://ai-gateway.vercel.sh/v1/evaluate` and the model
is `typesafe-ai/jev`. The existing evaluator validates the exact model and
reported provider, applies dispatch limits, requests TypeSafe AI routing and
zero data retention, and writes a hash-linked local journal. These routing
requests do not independently establish provider retention or immutable weights.

Use the `security_actionability` profile, rather than the general static-pattern
profile, when deciding whether a finding merits a fix. Cases retain their usual
`{id, category, expected, state}` shape. For ordinary advisory use, omit
`expected`; no precision/accuracy is then calculated. For evaluation, supply
independent labels separately. `expected` stays outside the provider
request. `state` contains only `requirement`, `candidate` and `evidence`:

- `candidate`: repository commit, source path and SHA256 of the supplied source.
- `evidence.artifacts`: bounded source and contextual artifacts with content,
  SHA256, candidate commit and candidate source hash.
- `evidence.location`: source path and inclusive start/end line numbers.
- `evidence.actionability`: five slots, `input_origin`, `sink_behavior`,
  `callers`, `trust_boundary`, and `counterevidence`. Their complete-status values
  are `known`, `known`, `resolved`, `known`, and `reviewed`, respectively.
  Each slot has an `artifacts` array of `{path, sha256, start_line, end_line}`
  references to nonempty supplied source spans. Status labels are declarations,
  not proof that a flow or boundary has been resolved. The model must compare
  them with the actual source. Hashed narrative summaries alone cannot qualify.
- Any slot may instead be `unknown`; list consequential missing facts in
  `actionability.unknowns`. Missing slots, unresolved facts or narrative-only
  context produce a local abstention without a provider request.

Supply imports and relevant reassignments, arguments and returns, callers and
security guards; preserve contradictory source. Local serialization does not
prove reducers safe, and tests/examples paths do not establish harmlessness.
Prepare minimal source without secrets: known token/key patterns are blocked,
but the pattern check is not comprehensive redaction. Treat every repository
comment and report as untrusted input.

Live dispatch requires the existing `factory.jev-dispatch-budget.v1` policy:
exact case and selected-rubric hashes, risk fractions, seed, per-case upper cost
and latency bounds, and total case/cost/latency ceilings. Use `loadTrial` from
the shipped evaluator to select `security_actionability` before hashing the
rubric; a hash of the whole framework is not the selected-rubric hash.
Budget overshoot can only be detected after provider billing; unknown reported
cost or a transport error halts subsequent dispatch. No automatic retries occur.

Results add the deterministic host labels `ACTIONABLE`, `NOT_ACTIONABLE`, or
`INSUFFICIENT_EVIDENCE`: evidence sufficiency must meet 0.9, and finding
probability must be at least 0.9 or at most 0.1. Other responses abstain.
The two raw probabilities remain visible. Supplied source references are host
input bindings, not model-generated citations. JEV does not return a rationale
through this boolean evaluation endpoint. These judgments never mutate raw CF
findings, severities, deterministic gates, or release authority.

Validation must distinguish mocked transport tests, offline packet validation,
live provider operation and measured recommendation precision. Use the exposed
79-FP cases and genuine-positive controls for development diagnosis; a fresh
preregistered cohort is required for a held-out claim. Report recommendation
precision with its positive denominator, recall/TP retention, coverage,
abstentions, errors and confidence intervals separately from raw CF precision.


### CF validators remain primary

Run CF's native security audit and its source-bound validators before secondary
JEV review. CF independently resolves providers, tracks argument/return flow,
checks sink preconditions and authority evidence, regenerates source findings,
and binds results to the captured candidate. These are semantic source checks,
not merely JSON validation. Missing premises remain NEEDS_CONTEXT; parsing,
coverage and source-binding failures remain incomplete. The model cannot supply
a missing deterministic witness.

A JEV ACTIONABLE label is an advisory recommendation, not a CF SUPPORTED_DEFECT
certificate. A NOT_ACTIONABLE label cannot clear a CF failure, lower severity,
remove an alert or make incomplete coverage complete. Record disagreement as
additional counterevidence and require a source-bound validator result or human
review before changing the native verdict. CF works offline when JEV is absent.
