# Spec: runtime-coverage-panel
Status: proposed
SpecFactor-target: 0.75

## MUST — Functional core
### Description
Code Factory Graph Ops reads a bounded Coverage.py JSON report from the current workspace and displays executed Python statement and branch coverage alongside recorded test cases and ForgeLine static test-intent attribution. It reports missing or invalid runtime evidence explicitly and offers file and line-level follow-up targets. The feature observes local test artifacts only; it does not run tests, approve changes, or certify quality.

### User roles
- Developer: runs a test command and inspects the local runtime coverage report.
- Reviewer: uses the displayed statement and branch gaps to choose follow-up tests.
- Graph Ops: reads and validates local coverage artifacts without executing code.

### Requirements (EARS)
- The system shall return aggregate statement and branch counts and percentages in schema `factory.runtime-coverage.v1` from Coverage.py JSON format version 7 reports at `.factory/test-reports/coverage.json` with branch collection enabled, for reports no larger than 16 MiB.
- The system shall show each included Python module with statement and branch counts, percentage, missing statement line numbers, missing branch locations, and a boolean `detail_truncated` field, with at most 20 missing lines and 20 missing branches per module.
- The system shall validate required JSON fields, nonnegative count ranges, rate consistency, input size at most 16 MiB, file count at most 5,000, workspace containment, the exact current `factoryline` Python source-file inventory, structural validation, arithmetic validation, line totals, branch totals, and every reported line/branch location against the current source file's physical line range; invalid or incomplete-scope reports shall return error code `RUNTIME_COVERAGE_INVALID`.
- When no coverage report exists at the documented path, Graph Ops shall return one snapshot with state `NOT_RUN`, null statement and branch percentages, and no fabricated zero-percent values.
- If a report is malformed, exceeds 16 MiB or 5,000 files, lacks branch data, has inconsistent aggregate or file totals, or names a path outside the workspace, Graph Ops shall return one `INCOMPLETE` snapshot, suppress all file details, and include an actionable reason.
- When a report is observed, Graph Ops shall display its SHA-256 digest and timezone-normalized report timestamp, label candidate binding `UNBOUND` unless an exact-command run receipt, current Git commit/worktree state, current production/test source hashes, report timestamp interval, and artifact hashes all match, and disclose that the unsigned receipt does not authenticate the runner or CI provider.
- The system shall show runtime statement/branch coverage, JUnit test counts, and ForgeLine static test-intent attribution under distinct labels including `FORGELINE_STATIC_TEST_INTENT`.
- The system shall return module-level coverage details under rule ID `RUNTIME_COVERAGE_DETAIL_AUTH` only when a client presents the Studio session token.
- The system shall return a Graph Ops summary without per-file coverage details under rule ID `RUNTIME_COVERAGE_SUMMARY_REDACTION`.
- The system shall return one `RUNTIME_COVERAGE_LIMITATION` string of at most 240 characters stating executed-line counts do not establish test assertion quality or software correctness.
- When the Ubuntu Python 3.11 CI matrix leg runs the full suite, the system shall emit the Coverage.py JSON report, Cobertura report, JUnit report, and run receipt under rule ID `RUNTIME_COVERAGE_CI_OUTPUTS` during that test run.
- When the Ubuntu Python 3.11 CI matrix leg completes the full suite, the system shall emit one test artifact containing all four runtime coverage artifacts under rule ID `RUNTIME_COVERAGE_CI_UPLOAD`.
- When the local full-suite runner completes, the system shall enforce `RUNTIME_COVERAGE_LOCAL_IDENTITY` by emitting one explicitly unauthenticated local receipt with the exact supported pytest command, Git commit, and worktree state.
- The system shall record the runner environment and timezone-aware start and end timestamps in the local full-suite receipt under rule ID `RUNTIME_COVERAGE_LOCAL_ENVIRONMENT`.
- The system shall enforce `RUNTIME_COVERAGE_LOCAL_SOURCE_DIGESTS` by recording before-and-after production and test source hashes in the local full-suite receipt.
- The system shall enforce `RUNTIME_COVERAGE_LOCAL_ARTIFACT_DIGESTS` by recording content hashes for JUnit, Coverage.py JSON, and Cobertura reports in the local full-suite receipt.
- When the Ubuntu Python 3.11 full-suite CI leg completes, the system shall enforce `RUNTIME_COVERAGE_CI_IDENTITY` by emitting one explicitly unauthenticated CI receipt with the exact supported pytest command, Git commit, clean-worktree state, and GitHub Actions run identity.
- The system shall record the runner environment and timezone-aware start and end timestamps in the CI full-suite receipt under rule ID `RUNTIME_COVERAGE_CI_ENVIRONMENT`.
- The system shall enforce `RUNTIME_COVERAGE_CI_SOURCE_DIGESTS` by recording before-and-after production and test source hashes in the CI full-suite receipt.
- The system shall enforce `RUNTIME_COVERAGE_CI_ARTIFACT_DIGESTS` by recording content hashes for JUnit, Coverage.py JSON, and Cobertura reports in the CI full-suite receipt.
- The system shall reject a run receipt under rule ID `RUNTIME_COVERAGE_REPORT_TIME_BINDING` when the normalized Coverage.py report timestamp falls outside its recorded test-run interval.
- When tests fail, source changes during execution, reports are missing, commit or worktree binding is wrong, or the CI checkout is unclean, the system shall enforce `RUNTIME_COVERAGE_FAILURE_STATE` by emitting a non-passing run receipt.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Valid line and branch coverage is visible
  Given a valid report at `.factory/test-reports/coverage.json` with Coverage.py JSON format version 7, size no larger than 16 MiB, and branch coverage enabled
  When Graph Ops validates required fields, nonnegative counts, arithmetic consistency, file containment, source-bounded line/branch locations, and at most 5,000 Python modules
  Then the `factory.runtime-coverage.v1` summary reports observed statement and branch counts and percentages separately
  And the token-protected detail response returns every included module with counts and percentages
  And each module contains at most 20 missing-line and 20 missing-branch locations and sets `detail_truncated` when details are omitted
  And the UI labels the report candidate binding UNBOUND unless the run receipt and source hashes validate

Scenario: No report is not a zero-percent result
  Given the workspace has no Coverage.py JSON report
  When Graph Ops projects audit results
  Then runtime coverage state is NOT_RUN
  And line and branch percentages are shown as unavailable rather than zero

Scenario: Invalid or unsafe reports fail closed
  Given the report is malformed, larger than 16 MiB, has more than 5,000 files, lacks branch data, omits or adds a Python module relative to the exact current `factoryline` source inventory, has contradictory aggregate or file totals, reports a line or branch location beyond the actual source file, or names a path outside the workspace
  When Graph Ops reads the report
  Then runtime coverage state is INCOMPLETE with error code `RUNTIME_COVERAGE_INVALID` and an actionable reason
  And no per-file details are returned

Scenario: Coverage evidence remains distinct from static attribution and JUnit
  Given ForgeLine static attribution, JUnit case results, and Coverage.py runtime data are present
  When Graph Ops displays audit results
  Then runtime statement and branch metrics, JUnit case counts, and `FORGELINE_STATIC_TEST_INTENT` each have a distinct label
  And no metric is described as certification or proof of correctness

Scenario: Coverage details require the local Studio token
  Given a valid report has up to 5,000 modules with bounded line and branch gaps
  When a client requests module details
  Then `RUNTIME_COVERAGE_DETAIL_AUTH` denies the request without its session token
  And `RUNTIME_COVERAGE_SUMMARY_REDACTION` omits per-file coverage details from the Graph Ops summary
  And the authorized local detail response returns the validated module rows

Scenario: Coverage does not claim correctness
  Given a runtime coverage report is observed
  When Graph Ops renders its result
  Then the report includes `RUNTIME_COVERAGE_LIMITATION` with at most 240 characters stating executed-line counts do not establish assertion quality or software correctness
  And no release-approval or correctness-certification result is returned

Scenario: CI captures coverage in the existing suite execution
  Given the existing Ubuntu Python 3.11 matrix leg starts from a clean checkout and runs the full test suite with branch collection enabled
  When the Ubuntu Python 3.11 CI matrix leg completes the full suite
  Then `RUNTIME_COVERAGE_CI_OUTPUTS` emits the Coverage.py JSON report, Cobertura report, JUnit report, and run receipt during that test run
  And `RUNTIME_COVERAGE_CI_UPLOAD` emits one test artifact containing all four runtime coverage artifacts
  And the workflow creates no additional matrix leg

Scenario: Local full-suite receipt binds the local run
  Given the local full-suite runner starts with production and test Python-source hash inventories
  When the local full-suite runner completes the exact branch-aware pytest command
  Then `RUNTIME_COVERAGE_LOCAL_IDENTITY` emits one explicitly unauthenticated local receipt with the exact supported pytest command, Git commit, and worktree state
  And `RUNTIME_COVERAGE_LOCAL_ENVIRONMENT` records the runner environment and timezone-aware start and end timestamps in the local full-suite receipt
  And `RUNTIME_COVERAGE_LOCAL_SOURCE_DIGESTS` records before-and-after production and test source hashes in the local full-suite receipt
  And `RUNTIME_COVERAGE_LOCAL_ARTIFACT_DIGESTS` records content hashes for JUnit, Coverage.py JSON, and Cobertura reports in the local full-suite receipt
  And `RUNTIME_COVERAGE_REPORT_TIME_BINDING` accepts the normalized Coverage.py report timestamp only inside the recorded local test-run interval

Scenario: CI full-suite receipt binds the clean CI run
  Given the Ubuntu Python 3.11 CI leg starts with production and test Python-source hash inventories
  When the Ubuntu Python 3.11 full-suite CI leg completes the exact branch-aware pytest command
  Then `RUNTIME_COVERAGE_CI_IDENTITY` emits one explicitly unauthenticated CI receipt with the exact supported pytest command, Git commit, clean-worktree state, and CI runner run identity
  And `RUNTIME_COVERAGE_CI_ENVIRONMENT` records the runner environment and timezone-aware start and end timestamps in the CI full-suite receipt
  And `RUNTIME_COVERAGE_CI_SOURCE_DIGESTS` records before-and-after production and test source hashes in the CI full-suite receipt
  And `RUNTIME_COVERAGE_CI_ARTIFACT_DIGESTS` records content hashes for JUnit, Coverage.py JSON, and Cobertura reports in the CI full-suite receipt
  And `RUNTIME_COVERAGE_REPORT_TIME_BINDING` accepts the normalized Coverage.py report timestamp only inside the recorded CI test-run interval
  And the receipt is explicitly unauthenticated until verified by a supported signature system
  And `RUNTIME_COVERAGE_FAILURE_STATE` emits a non-passing receipt for failed tests, changed source, stale or out-of-run reports, mismatched commit, missing artifacts, or an unclean CI checkout
```

## SHOULD — Technical/structural
- ADR references: none; extend current pytest-cov, JUnit artifact, Graph Ops snapshot, and loopback token API patterns.
- Data model: read-only Coverage.py JSON summary plus optional `factory.runtime-coverage-run.v1` receipt; source and artifact hashes use `sha256` digests; the run identity binds the Git `HEAD` commit; no database or persisted service state.
- Artifact contract: `.factory/test-reports/coverage.json` is Coverage.py JSON, `.factory/test-reports/coverage.xml` is Cobertura XML, and `.factory/test-reports/pytest.xml` is JUnit XML.
- API contract: Graph Ops snapshot gains a `runtime_coverage` summary; the loopback Studio API endpoint `GET /api/coverage-report` returns token-protected details in the same schema with bounded module rows.

## SHOULD NOT — Implementation details
- Do not combine runtime coverage with ForgeLine static attribution or JUnit test totals.
- Do not infer coverage from source inventories, test names, CI badges, or old/stale reports.
- Do not upload source code or call an external coverage service.
