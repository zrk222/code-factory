# TASK PACKET T1 — runtime-coverage-panel
<!-- One session. Finish, verify, stop. Context resets after this. -->

## Your single task
implement strict version-7 JSON validation, arithmetic aggregation, containment, stable Python-source hashing, and unauthenticated receipt handling.

## Slice (you may only create/modify files here + tests)
factoryline

## Files in scope (R_f — read nothing else except context/PROGRESS.md)
- factoryline/runtime_coverage.py

## Governing spec excerpt
### Governing requirements (complete blocks)
- The system shall return aggregate statement and branch counts and percentages in schema `factory.runtime-coverage.v1` from Coverage.py JSON format version 7 reports at `.factory/test-reports/coverage.json` with branch collection enabled, for reports no larger than 16 MiB.
- The system shall show each included Python module with statement and branch counts, percentage, missing statement line numbers, missing branch locations, and a boolean `detail_truncated` field, with at most 20 missing lines and 20 missing branches per module.
- The system shall validate required JSON fields, nonnegative count ranges, rate consistency, input size at most 16 MiB, file count at most 5,000, workspace containment, structural validation, arithmetic validation, line totals, and branch totals; invalid reports shall return error code `RUNTIME_COVERAGE_INVALID`.
- When a report is observed, Graph Ops shall display its SHA-256 digest and report timestamp, label candidate binding `UNBOUND` unless a run receipt and current-source hashes are verified, and disclose that a local receipt does not authenticate the runner.
- When the Ubuntu Python 3.11 CI matrix leg runs the existing full suite, it shall record `coverage.json` and Cobertura `coverage.xml` in that same test run and upload them as required test artifacts without adding another matrix leg.
- When the local audit test runner executes the full suite with `--cov=factoryline` and `--cov-branch`, the system shall write one receipt containing the exact command, commit, environment, start/end timestamps, Python-source hashes before and after, and SHA-256 digests for JUnit XML, coverage JSON, and coverage XML; changed source, failed tests, or missing output shall make that receipt non-passing.
- Data model: read-only Coverage.py JSON summary plus optional local `factory.runtime-coverage-run.v1` receipt; no database or persisted service state.
- Do not infer coverage from source inventories, test names, CI badges, or old/stale reports.
- Do not upload source code or call an external coverage service.

## CONSTITUTION DIGEST: one task only; read ONLY listed files; tests ship with code; never touch skeleton/; never add deps without ADR; never leave stubs; decision logic goes to the factory, not inline; stop and ask on ambiguity.

## Definition of done
Run: `rtk proxy python -m py_compile factoryline/runtime_coverage.py` — must pass. Then STOP and report the diff summary.
