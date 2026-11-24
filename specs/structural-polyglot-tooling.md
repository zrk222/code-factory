# Spec: structural-polyglot-tooling
Status: draft

## MUST — Functional core

Give operators qualified native analysis for Java, C# and Go when their sources and dependencies are supported in an offline worker. Surface dependency, SDK, module-root and unsupported-language gaps in the existing evidence paths. These changes are separate from scanner rule and benchmark tuning.

### Requirements (EARS)

- The system shall verify `REQ_TOOL_IDENTITY` and reject an engine, SDK input or query suite with an unmatched identity.
- The system shall verify `REQ_OFFLINE_RECEIPT` and emit the source-bound receipt under network isolation.
- The system shall verify `REQ_MISSING_PREREQUISITE` and return incomplete for an unavailable SDK, module root, local dependency or extractor.
- The system shall verify `REQ_PHP_FALLBACK` and return the existing local-pattern lane for PHP when CodeQL extraction is unsupported.
- The system shall verify `REQ_PHP_INTERFILE` and account for ordinary PHP sources under the explicitly selected cross-file profile while leaving Blade inventories incomplete.
- The system shall verify `REQ_QUALIFICATION_EVIDENCE` and record the candidate, image, host and each control result.
- The system shall verify `REQ_COMPARISON_INVARIANCE` and reject a cold/warm comparison if output or coverage differs.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Candidate-native worker admission
  Given REQ_TOOL_IDENTITY and a complete benign language fixture
  When the worker runs with the declared source mounted read-only and network disabled
  Then REQ_OFFLINE_RECEIPT and REQ_QUALIFICATION_EVIDENCE bind the observed source and report

Scenario: Missing foreign toolchain or source
  Given an absent SDK, missing module root or unsupported extractor
  When the structural qualification runs
  Then REQ_MISSING_PREREQUISITE identifies the specific unmet prerequisite
  And REQ_PHP_FALLBACK preserves the existing local-pattern lane

Scenario: Compare measured execution
  Given matched cold and warm runs
  When either output or coverage differs
  Then REQ_COMPARISON_INVARIANCE rejects the comparison

Scenario: Opt-in PHP cross-file execution
  Given REQ_PHP_INTERFILE and an exact two-file PHP marker fixture
  When the worker runs with its inspected image, profile and rule hashes
  Then the positive trace includes both source files and the safe and disabled controls contain no findings
```

## SHOULD — Technical/structural

- Reuse native profile execution, target selection and output normalization.
- Source-only Java excludes Kotlin and source that a build would generate.
- Preserve fixed argv, non-root execution, no network and host authorization checks.
- Keep test fixtures and worker artifacts separate from the recall corpus.

Signed six-family qualification uses a separate end-to-end candidate run.
