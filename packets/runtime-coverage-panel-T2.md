# TASK PACKET T2 — runtime-coverage-panel
<!-- One session. Finish, verify, stop. Context resets after this. -->

## Your single task
add behavioral valid, missing, malformed, oversize, inconsistent, escaped-path, truncation, and source-hash-binding tests.

## Slice (you may only create/modify files here + tests)
tests

## Files in scope (R_f — read nothing else except context/PROGRESS.md)
- tests/test_runtime_coverage.py

## Governing spec excerpt
### Governing requirements (complete blocks)
- Reviewer: uses the displayed statement and branch gaps to choose follow-up tests.
- The system shall show each included Python module with statement and branch counts, percentage, missing statement line numbers, missing branch locations, and a boolean `detail_truncated` field, with at most 20 missing lines and 20 missing branches per module.
- When no coverage report exists at the documented path, Graph Ops shall return one snapshot with state `NOT_RUN`, null statement and branch percentages, and no fabricated zero-percent values.
- If a report is malformed, exceeds 16 MiB or 5,000 files, lacks branch data, has inconsistent aggregate or file totals, or names a path outside the workspace, Graph Ops shall return one `INCOMPLETE` snapshot, suppress all file details, and include an actionable reason.
- When a report is observed, Graph Ops shall display its SHA-256 digest and report timestamp, label candidate binding `UNBOUND` unless a run receipt and current-source hashes are verified, and disclose that a local receipt does not authenticate the runner.
- When the local audit test runner executes the full suite with `--cov=factoryline` and `--cov-branch`, the system shall write one receipt containing the exact command, commit, environment, start/end timestamps, Python-source hashes before and after, and SHA-256 digests for JUnit XML, coverage JSON, and coverage XML; changed source, failed tests, or missing output shall make that receipt non-passing.
- Do not infer coverage from source inventories, test names, CI badges, or old/stale reports.
- Do not upload source code or call an external coverage service.

### Acceptance (verbatim — do not reinterpret)
```gherkin
Scenario: Valid line and branch coverage is visible
  Given a valid report at `.factory/test-reports/coverage.json` with Coverage.py JSON format version 7, size no larger than 16 MiB, and branch coverage enabled
  When Graph Ops validates required fields, nonnegative counts, arithmetic consistency, file containment, and at most 5,000 Python modules
  Then the `factory.runtime-coverage.v1` summary reports observed statement and branch counts and percentages separately
  And the token-protected detail API returns every included module with counts and percentages
  And each module contains at most 20 missing-line and 20 missing-branch locations and sets `detail_truncated` when details are omitted
  And the UI labels the report candidate binding UNBOUND unless the run receipt and source hashes validate

## CONSTITUTION DIGEST: one task only; read ONLY listed files; tests ship with code; never touch skeleton/; never add deps without ADR; never leave stubs; decision logic goes to the factory, not inline; stop and ask on ambiguity.

## Definition of done
Run: `$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; rtk proxy python -m pytest -p pytest_asyncio.plugin -q tests/test_runtime_coverage.py` — must pass. Then STOP and report the diff summary.
