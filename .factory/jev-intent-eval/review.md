# Independent Jev test-oracle rubric review

## Frozen scope

This review covers 12 constructed Python source excerpts in `independent-cases.json`: six hollow and six meaningful examples. Labels and rationales are held in the case artifact, outside `state`, and were frozen before any model evaluation. The candidate revision is base commit `a7946b998cc796186150d76463db159fc1f6ba00`; snippets are explicitly constructed and are not represented as source collected from that revision or as executed tests. Source-only adjudication is limited to control flow visible in each excerpt. No provider/model call or runtime execution was made.

The review sample includes misleading names/docstrings/comments, smoke-only setup, swallowed assertions, uncalled and directly called callbacks, real mock interaction assertions, expected-exception contexts, explicit failure when an expected exception is absent, and a smoke invocation accompanied by an actual assertion. External registration/helper behavior is excluded when unresolved; no conclusion about dynamic dispatch or runtime behavior is made.

## Rubric assessment

The added instruction that names, docstrings, comments, annotations, and expected labels express intent rather than executable checks is sound. It directs attention to source control flow and should reduce false negatives where labels promise behavior unsupported by the body. The added statement that setup, cleanup, registration, logging, and calls that only establish “does not raise” are not behavioral oracles is also sound for this profile’s effective-failure-check criterion. It should not be generalized into a claim that smoke tests have no engineering value; they simply do not prove a specific behavioral contract without an outcome or failure check.

The expected-exception clarification is sound and useful: an explicit `pytest.raises` context and explicit failure on a missing exception are checks, while an exception merely possible during setup is not. Keep the source-only boundary. Do not infer exception behavior from an unresolved external call, decorator, fixture, or dynamic callback. A test may still be meaningful because another visible assertion executes, even if a separate assertion is swallowed.

The callback instruction is appropriate but should remain narrowly phrased: count a nested check only where the supplied source establishes its call path. Merely registering a callback is ambiguous without resolver/caller context and should be excluded or adjudicated unresolved rather than treated as definitely called or uncalled. The constructed cases avoid claiming registration behavior.

The profile’s `evidence_instructions` still tests only whether Python test source text is present. That separation is coherent if interpreted strictly as packet sufficiency; it must not be mistaken for evidence that the test has an effective oracle. The finding instructions, not this sufficiency question, evaluate control flow.

## Artifacts and hashes

- Frozen cases: SHA-256 `1a40ce88b36af17e89af5b3e82fb2e28ae487f380d4f76cfd1d9675e2c231a7c`
- Current on-disk rubric (`factoryline/data/judge_framework.json`): SHA-256 `10705987b26729e9e6852e093241168d71cf6dd603c196166290cb3d65e0e03b`
- Validator (`scripts/evaluate_jev.mjs`): SHA-256 `5475e7250efd7b21a719ea70f39a3ec62bd00ec023be646a9e9d0987a7e5b262`
- Source container (`tests/fixtures/external_oracle_cases.json`): SHA-256 `dbeede177e562da0f42fa2b1379e71eec4248731931b2f7fccc814cedfb1eb11`
- Candidate commit: `a7946b998cc796186150d76463db159fc1f6ba00`

The validator requires a 40-hex candidate commit, nonempty path and source, exact excerpt SHA-256, and—when supplied—a selected test name whose declared start line matches a function definition and whose range falls within the excerpt. It does not authenticate the path against the commit, prove that the excerpt was collected from that file, or establish true function boundaries. Here the examples are deliberately constructed, so their path/commit fields are schema-valid identity placeholders, not source provenance. Treat this file as an independent rubric challenge set, not an admissible provenance-bound holdout or an accuracy benchmark.

## Follow-up review: rubric 1.2.4

Re-read the current `test_oracle` profile before considering any live trial output. Current rubric version is **1.2.4** (SHA-256 `2ed6a5eee5543789612f81d15e0f50492cf2bedbcc17e5a4f0722e8bd71ae022`). The frozen 12-case file is unchanged (SHA-256 `1a40ce88b36af17e89af5b3e82fb2e28ae487f380d4f76cfd1d9675e2c231a7c`); validator hash remains `5475e7250efd7b21a719ea70f39a3ec62bd00ec023be646a9e9d0987a7e5b262`.

### Assessment of 1.2.4 additions

The explicit **ANY-effective-check** rule is sound and closes a real ambiguity: if one meaningful check can fail and that failure propagates to the selected test, an ineffective or swallowed decoy does not make the whole test hollow. The polarity should be based on a check that is both reachable and failure-propagating, not merely the lexical presence of an assertion.

The directly-called local callback clarification is sound with its stated condition. Trace into the supplied callback body and surrounding handlers; count its assertion only if the call path reaches it and `AssertionError` can escape to the selected test. A broad handler that catches and suppresses the assertion still makes that callback check ineffective. Definition, registration, or a call into unresolved external/dynamic dispatch alone is insufficient. This avoids making the rule permissive toward swallowed callbacks.

The false criterion examples provide useful contextual confirmation for the two subtle positive patterns (called local callback and a later assertion after a swallowed one). They do not authorize counting every assertion in the test: reachability, meaning, and propagation remain necessary. The smoke/intent language and expected-exception distinction reviewed above remain sound.

### Scope and follow-up

This is an independent source-level rubric assessment, not a production or runtime conclusion. The frozen snippets support a targeted edge review; they are constructed examples with placeholder repository identity fields and are not provenance-authenticated collected tests. Do not interpret their score, or a single model run on them, as accuracy or calibration. The `evidence_instructions` question remains source-presence-only and should stay separate from whether that source contains an effective oracle.

No labels, case inputs, or trial outputs were changed during this follow-up. Current 1.2.4 review verdict: the ANY-check and called-callback additions are directionally correct and not over-permissive as long as propagation is enforced through all relevant handlers and unresolved callback behavior remains unresolved.

## Git artifact normalization
Frozen provider-input bytes used CRLF; Git normalizes this JSON and review to LF. JSON content and case labels remain identical; no evaluation was rerun or relabelled. The provider input hash above refers to the original bytes. Published LF case-file SHA-256: 644cd24d57563135aa571f27ff7407bbd87ab45b8da81348c1908104061ac2fc.
