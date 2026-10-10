# Focused test input review

**Scope:** Read-only review of the current changes to `scripts/evaluate_jev.mjs`, `scripts/evaluate_jev.test.mjs`, and `factoryline/data/judge_framework.json`, plus `.factory/independent-ai/focused-input-tests.log`. No source edits or external calls.

## Assessment

No blocking defect found in this bounded review.

- The optional `evidence.selected_test` declaration binds a Python `def` name at its declared start line and requires integer original-file start/end coordinates within the digest-bound source excerpt. `source_start_line` supports excerpt offsets; omitted offset defaults to line 1. The supplied tests cover a full-source target, indented CRLF excerpt at offset 503, missing name, wrong name, out-of-range and malformed coordinates, and confirm invalid declarations reject before the mocked provider is called.
- Source digest computation uses UTF-8 bytes of the supplied source string; splitting accepts LF and CRLF. The declaration validates location/name consistency only. It does not establish test collection, complete function boundaries, upstream provenance, or correctness of excerpt offsets. Those limits are explicitly described in framework guidance.
- When `selected_test` is absent, the host does not enforce the framework's “one unambiguous target test” direction; that remains model-side guidance. Existing callers without the optional field retain prior behavior. The expanded rubric tells the model not to borrow assertions from unrelated tests and limits external helper conclusions to supplied context.
- `focused-input-tests.log` records 57 tests passing, including the selected-test binding test. This supports the tested code paths only; it does not prove model adjudication quality, runtime execution of candidate Python tests, or repository/source authenticity.

**Applicability:** This review covers only the listed diff and test log. The new declaration check applies only when the selected-test field is supplied on the test-oracle profile; it is not a general source verifier. Review remains advisory and conveys no scanner, CI, release, or human-certification authority.
