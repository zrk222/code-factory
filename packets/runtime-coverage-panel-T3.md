# TASK PACKET T3 — runtime-coverage-panel
<!-- One session. Finish, verify, stop. Context resets after this. -->

## Your single task
add runtime coverage summary to the read-only graph payload without file details.

## Slice (you may only create/modify files here + tests)
factoryline

## Files in scope (R_f — read nothing else except context/PROGRESS.md)
- factoryline/graph_ops.py

## Governing spec excerpt
### Governing requirements (complete blocks)
- Developer: runs a test command and inspects the local runtime coverage report.
- Graph Ops: reads and validates local coverage artifacts without executing code.
- The system shall return aggregate statement and branch counts and percentages in schema `factory.runtime-coverage.v1` from Coverage.py JSON format version 7 reports at `.factory/test-reports/coverage.json` with branch collection enabled, for reports no larger than 16 MiB.
- The system shall validate required JSON fields, nonnegative count ranges, rate consistency, input size at most 16 MiB, file count at most 5,000, workspace containment, structural validation, arithmetic validation, line totals, and branch totals; invalid reports shall return error code `RUNTIME_COVERAGE_INVALID`.
- When no coverage report exists at the documented path, Graph Ops shall return one snapshot with state `NOT_RUN`, null statement and branch percentages, and no fabricated zero-percent values.
- If a report is malformed, exceeds 16 MiB or 5,000 files, lacks branch data, has inconsistent aggregate or file totals, or names a path outside the workspace, Graph Ops shall return one `INCOMPLETE` snapshot, suppress all file details, and include an actionable reason.
- When a report is observed, Graph Ops shall display its SHA-256 digest and report timestamp, label candidate binding `UNBOUND` unless a run receipt and current-source hashes are verified, and disclose that a local receipt does not authenticate the runner.
- The system shall show runtime statement/branch coverage, JUnit test counts, and ForgeLine static test-intent attribution under distinct labels including `FORGELINE_STATIC_TEST_INTENT`.
- The system shall return module-level coverage details only through token-protected `GET /api/coverage-report` on the existing loopback Studio API; the summary endpoint shall omit per-file details.
- The system shall return one `RUNTIME_COVERAGE_LIMITATION` string of at most 240 characters stating executed-line counts do not establish test assertion quality or software correctness.
- When the Ubuntu Python 3.11 CI matrix leg runs the existing full suite, it shall record `coverage.json` and Cobertura `coverage.xml` in that same test run and upload them as required test artifacts without adding another matrix leg.
- When the local audit test runner executes the full suite with `--cov=factoryline` and `--cov-branch`, the system shall write one receipt containing the exact command, commit, environment, start/end timestamps, Python-source hashes before and after, and SHA-256 digests f

## CONSTITUTION DIGEST: one task only; read ONLY listed files; tests ship with code; never touch skeleton/; never add deps without ADR; never leave stubs; decision logic goes to the factory, not inline; stop and ask on ambiguity.

## Definition of done
Run: `rtk proxy python -m py_compile factoryline/graph_ops.py` — must pass. Then STOP and report the diff summary.
