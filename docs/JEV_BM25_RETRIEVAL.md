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
