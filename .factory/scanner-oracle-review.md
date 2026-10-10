# Bounded scanner-oracle review

Independent agent review found and corrected an unrelated-call bypass in mock
self-check attribution and string-target serializer replacement through patch
or monkeypatch. The reviewer retracted an incorrect decorator-AST concern after
running the actual decorator regression (1 passed). Final bounded review PASS;
no claim of independent human review or production accuracy.

Scope: Python AST recognition and test-source byte provenance; no runtime code
execution by the scanner, no network calls, no new source module, no changed
release authority or budgets. UI accessibility and external publication are not
applicable. Performance remains bounded by the existing source/import limits;
real-repository elapsed times are observations, not a speedup claim.

Acceptance: recognize argument/await and expected-exception checks; keep direct
mock self-checks, swallowed/unreachable failures, and unproven deserialization
blocking or reviewable. Preserve direct local test roundtrip evidence at INFO.
External-source corpus is public regression evidence, never held-out accuracy.
