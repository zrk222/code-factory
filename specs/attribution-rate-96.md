# Spec: attribution-rate-96 (98% extension)
Status: proposed
SpecFactor-target: 0.75

## MUST — Functional core
### Description
Raise the repository-wide ForgeLine function-level test-intent attribution rate from the latest measured 1,026/1,065 (96.25%) to at least 98% by adding behavior assertions for currently unattributed functions. The current unchanged inventory is 1,067; acceptance requires at least 1,046 attributed functions (98.03%). ForgeLine's current metric is a static function-name match against test source, not runtime coverage or proof of correctness.

### User roles
- Maintainer: reviews the selected gaps, behavior assertions, and exact report.
- ForgeLine QA: inventories the unchanged repository-wide production source set and reports attribution.
- Test runner: executes the new tests and existing suite under the project's pinned test command.

### Requirements (EARS)
- The system shall emit a provenance record containing the installed ForgeLine version, source commit, repository-wide scope, function inventory, and configured threshold without modifying those values.
- The system shall count a function as attributed only after an executed test calls the function and asserts its observable result.
- When a function has positive and negative or boundary outcomes, the tests shall assert each applicable outcome; the workflow shall reject symbol-only imports, comments, strings, callable checks, and test-name-only evidence.
- If test evidence is missing, stale, failing, or detached from the current candidate bytes, the workflow shall reject the evidence and record the attribution result as incomplete.
- The system shall not modify ForgeLine's attribution algorithm or configuration, change the scan scope, exclude functions/files, raise thresholds, rename implementation symbols, or add production-code marker references to improve the percentage.
- When the repository-wide ForgeLine report is produced, the QA stage shall emit exactly 1,067 function records and the numerator, denominator, rate, grade, composite, version, and source provenance.
- The system shall accept the attribution improvement only when all focused tests and the full repository suite pass.
- The system shall hash-bind candidate test files, the ForgeLine report, and executed test logs in the project-neutral workflow-audit contract.
- The public source preview shall identify the 0.47.0 fixes, changes, additions, and measured improvements; describe CF/FL as a robust code-audit factory; and disclose the attribution metric's static nature, current scan limits, and unpublished candidate status.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Measured repo-wide attribution reaches the target without scope changes
  Given the fixed 1,067-function ForgeLine repository-wide baseline
  When all candidate tests pass and ForgeLine audits the repository
  Then the report checks the same repository-wide source inventory and attributes at least 1,046 functions (at least 98%)
  And the report keeps the actual ForgeLine source provenance and labels coverage as test intent

Scenario: Hollow evidence cannot increase attribution
  Given a candidate adds only an import, mention, comment, string, or callable assertion for an unattributed function
  When the test suite and ForgeLine audit run
  Then the target is not accepted as completed evidence
  And the implementation remains in the unattributed set unless a behavior assertion exercises it

Scenario: Failing or stale tests block the claim
  Given a behavior test fails or its candidate hash differs from the bound contract
  When the workflow evidence gate evaluates the candidate
  Then the attribution improvement remains incomplete

Scenario: Preview describes the candidate without overstating its audit
  Given the current local ForgeLine report and implemented candidate changes
  When the GitHub and Hugging Face source previews are reviewed
  Then fixed, changed, added, and improved work is described accurately
  And the 98.03% static test-intent attribution is not called runtime coverage
  And neither preview claims certification or provider publication
```

## SHOULD — Technical/structural
- ADR references: none; tests only, with no production behavior or tool configuration changes.
- Data model: existing ForgeLine `Attribution` report; numerator and denominator remain intact.
- API contract: existing `forge qa --repo-wide --root .` JSON output.

## SHOULD NOT — Implementation details
- No score tuning, scanner patch, scope pruning, static token-only tests, or broad generated fixtures.
- Do not claim runtime coverage, security certification, or replacement of unit tests from this metric.
