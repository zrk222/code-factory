# Spec: h1-source-attribution
Status: draft | approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Add bounded, privacy-safe timing for selected existing static-scan source read, hash, AST parse, and import-index operations to the invocation-local lifecycle telemetry. This slice does not claim complete attribution of every parser or hash in the broader audit pipeline.

### User roles
- CLI and audit maintainers reading local lifecycle receipts.

### Requirements (EARS)
- The system shall emit measured selected static-scan operation totals while preserving operation values, exceptions, audit findings, and semantic digests.
- The system shall emit no more than 12 phase rows and report dropped calls and selected-operation coverage.
- When selected source phases are absent, the system shall emit `not_observed`; when a selected source phase fails or is dropped, the system shall emit incomplete coverage without exception text, source, or paths.
- If telemetry is disabled or outside an active invocation, the system shall preserve existing behavior without additional source reads.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: selected source-bearing static scan attribution
  Given an active invocation and a source-bearing static scan
  When selected bounded source operations complete
  Then the receipt reports their observed phases and the `selected_static_scan_operations` scope, while scan semantics match telemetry-disabled execution

Scenario: no source or failed phase
  Given no Python source files or a selected source-operation failure
  When the invocation completes
  Then the existing outcome is preserved and attribution is not_observed or incomplete without private details

Scenario: phase capacity is exceeded
  Given the invocation has recorded 12 phases
  When another recognized phase is measured
  Then the receipt remains bounded and reports the dropped observation and incomplete coverage
```

## SHOULD — Technical/structural
- ADR references: none
- Data model: bounded lifecycle receipt phase metadata; semantic scan and proof digests unchanged
- API contract: private helpers only; no public API change
- Coverage scope: `selected_static_scan_operations`; config/runtime-input and AST/hash operations outside the listed scan boundaries remain excluded

## SHOULD NOT — Implementation details
- No new module, service, source reread, cap increase, or performance claim.

### Declared facts
- `source_phase_observed`: a fixed source phase row was recorded in this invocation.
- `source_phase_failed_or_dropped`: a selected source phase failed or could not fit the row bound.
- `source_phase_rows_within_bound`: selected source rows were retained within the existing 12-row limit.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | source_phase_observed is false | emit `not_observed` |
| 2 | source_phase_failed_or_dropped is true | emit incomplete attribution and preserve command behavior |
| 3 | source_phase_rows_within_bound is true | record aggregate elapsed/call counts for covered operations |
