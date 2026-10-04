# TASK PACKET T7 — runtime-coverage-panel
<!-- One session. Finish, verify, stop. Context resets after this. -->

## Your single task
add pytest-cov 7.x to development dependencies only.

## Slice (you may only create/modify files here + tests)
pyproject.toml

## Files in scope (R_f — read nothing else except context/PROGRESS.md)
- pyproject.toml

## Governing spec excerpt
### Governing requirements (complete blocks)
- The system shall return module-level coverage details only through token-protected `GET /api/coverage-report` on the existing loopback Studio API; the summary endpoint shall omit per-file details.
- ADR references: none; extend current pytest-cov, JUnit artifact, Graph Ops snapshot, and loopback token API patterns.
- Data model: read-only Coverage.py JSON summary plus optional local `factory.runtime-coverage-run.v1` receipt; no database or persisted service state.

### Acceptance (verbatim — do not reinterpret)
```gherkin
Scenario: Valid line and branch coverage is visible
  Given a valid report at `.factory/test-reports/coverage.json` with Coverage.py JSON format version 7, size no larger than 16 MiB, and branch coverage enabled
  When Graph Ops validates required fields, nonnegative counts, arithmetic consistency, file containment, and at most 5,000 Python modules
  Then the `factory.runtime-coverage.v1` summary reports observed statement and branch counts and percentages separately
  And the token-protected detail API returns every included module with counts and percentages
  And each module contains at most 20 missing-line and 20 missing-branch locations and sets `detail_truncated` when details are omitted
  And the UI labels the report candidate binding UNBOUND unless the run receipt and source hashes validate

Scenario: No report is not a zero-percent result
  Given the workspace has no Coverage.py JSON report
  When Graph Ops projects audit results
  Then runtime coverage state is NOT_RUN
  And line and branch percentages are shown as unavailable rather than zero

Scenario: Invalid or unsafe reports fail closed
  Given the report is malformed, larger than 16 MiB, has more than 5,000 files, lacks branch data, has contradictory aggregate or file totals, or names a path outside the workspace
  When Graph Ops reads the report
  Then runtime coverage state is INCOMPLETE with error code `RUNTIME_COVERAGE_INVALID` and an actionable reason
  And no per-file details are returned

Scenario: Coverage evidence remains distinct from static attribution and JUnit
  Given ForgeLine static attribution, JUnit case results, and Coverage.py runtime data are present
  When Graph Ops displays audit results
  Then runtime statement and branch metrics, JUnit case counts, and `FORGELINE_STATIC_TEST_INTENT` each have a distinct label
  And no metric is described as certification or proof of correctness

## CONSTITUTION DIGEST: one task only; read ONLY listed files; tests ship with code; never touch skeleton/; never add deps without ADR; never leave stubs; decision logic goes to the factory, not inline; stop and ask on ambiguity.

## Definition of done
Run: `rtk proxy python -c "import tomllib;tomllib.load(open('pyproject.toml','rb'));print('pyproject parse PASS')"` — must pass. Then STOP and report the diff summary.
