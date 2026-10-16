# Plan: type-intent-attribution
Spec: specs/type-intent-attribution.md (approved within delegated bounded task)
Architect verdict: PASS

## Logical decomposition (phases)
1. Extract bounded type-checker selection helpers from the capped review_audits module into existing intent_quality without cyclic helper imports.
2. Resolve ty selection, exclusions, ignore inputs, rule state, and canonical assert_type binding to selected/excluded/unknown with complete cache identity.
3. Verify only focused cases, the retained bidict baseline/candidate, caps, reviewer acceptance, and hash-bound workflow evidence.

## Tasks (atomic - each independently shippable)
- [ ] T1 | slice=factoryline | files=factoryline/review_audits.py,factoryline/intent_quality.py,tests/test_review_audits.py | Affected audit regressions: 565 passed; final directory-ignore controls: 6 passed; final tox-context controls: 4 passed. Ruff and explicit C901 passed; architecture health passed. Final peer review accepted the exact source hashes. Workflow evidence gate and commit remain pending. Evidence and limits: `.factory/security-gap-review/type-intent-attribution/`.

## Observed outcome and limits

- The frozen bidict scan inspected all 20 discovered Python files. The retained `QUALITY_HOLLOW_TEST` for `tests/test_bidict.py::test_static_types` disappeared; two unrelated findings remain, so the overall scan state is `BLOCKED`, not clean.
- The adapter attributes a canonical `typing.assert_type` call only when ty selects the source, `type-assertion-failure` is enabled, the call is unsuppressed and unshadowed, and a bounded `tox.ini` declaration contains exactly `ty check`. Missing invocation evidence, explicit targets, unsupported globs, and ambiguous bindings retain the hollow-test finding.
- Installed `ty 0.0.1-alpha.29` was run on the frozen bidict checkout and exited 1 with 38 diagnostics, including type-assertion failures on `test_static_types`. No checker-pass receipt is emitted; the expected-type mutant was not run because the unmodified baseline already fails, so mutation sensitivity is unestablished.
- This is one retained-project reproduction, not a static-accuracy claim, checker-success claim, or production guarantee. Source-level test intent remains separate from observed checker execution.
