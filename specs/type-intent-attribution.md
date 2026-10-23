# Spec: type-intent-attribution
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core
### Description
Attribute a canonical `typing.assert_type` or `typing_extensions.assert_type` call as static type-intent evidence only when the supported checker configuration selects the test file and the assertion rule is enabled. Keep checker execution unverified without a current matching receipt.

### User roles
- Code Factory scanner operator
- Python project maintainer

### Requirements (EARS)
- The system shall emit `TYPE_SELECTION` as `selected`, `excluded`, or `unknown` and hash-bind the configuration, ignore, rule, invocation, and source inputs used to choose the state.
- The system shall emit `TYPE_INTENT_ATTRIBUTION` only when selection is selected, import provenance is canonical, the assertion rule is enabled, ignore state is clean, and no suppression applies.
- The system shall reject `TYPE_CREDIT_REJECTION` when the source is excluded or ignored, the effective assertion rule is disabled, a suppression applies, or import provenance is shadowed.
- If checker selection, configuration, invocation, ignore, rule, provider, or binding provenance is unsupported or ambiguous, the system shall emit no type-intent evidence and retain the `QUALITY_HOLLOW_TEST` candidate. It shall emit a concrete hollow-test finding only when source proves that no runtime oracle is present; otherwise it shall classify the oracle as unknown.
- The system shall record `EXECUTION_RECEIPT` as `NOT_VERIFIED` unless a current receipt matches source, checker, config, invocation, and environment, exits successfully, and reports no assertion diagnostics.
- The system shall emit `INDEPENDENT_FINDINGS` for unrelated weak-oracle and other quality findings after type-intent attribution.
- The captured provider-effect profile may trust canonical host stdlib `typing` import semantics only when the source inventory is complete and has no local `typing` shadow. For an inactive type-only fallback, the selected test body is analyzed separately, then excluded from the owner-effect proof. Every other owner function and fixture body remains in that proof. A sibling body may count as inert when it contains only a direct `from typing import assert_type` alias call or exact `typing.assert_type` module-alias call with two Name/Constant arguments, no keywords, and no nested calls; the captured import binding must itself remain stable and cannot be shadowed by parameters or local writes. Other reads, alias escapes, rebinding, arbitrary calls or writes, `typing_extensions` providers without source/version proof, or effects outside captured sources remain unresolved.
- Provider closure shall include the owner test module, captured ancestor `conftest.py` files, and their transitive local imports. The selected test function's decorators, defaults, annotations, and binding remain checked. Unresolved pytest plugin or lifecycle effects, or incomplete retained source inventory, shall keep runtime-oracle attribution unknown.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Included bidict-style assertion is attributed as type intent
  Given TYPE_SELECTION is selected and TYPE_INTENT_ATTRIBUTION has canonical import with enabled rule and clean ignore state
  And no suppression applies to the assert_type call
  When the scanner evaluates hollow-test evidence
  Then it emits TYPE_INTENT_ATTRIBUTION and records EXECUTION_RECEIPT as NOT_VERIFIED
  And INDEPENDENT_FINDINGS remain eligible

Scenario: Unsupported or excluded checker scope preserves the finding
  Given TYPE_SELECTION is excluded or unknown
  When the scanner evaluates an assert_type call
  Then it emits no type-intent evidence and retains the QUALITY_HOLLOW_TEST candidate
  And it emits QUALITY_HOLLOW_TEST only when source proves no runtime oracle exists
  And unresolved delegated behavior is classified as QUALITY_UNKNOWN_TEST_ORACLE

Scenario: Runtime behavior passed to an inactive type-only assertion stays unknown
  Given assert_type is inactive or provider provenance is unresolved
  And the asserted value is produced by an unresolved call
  When the scanner evaluates hollow-test evidence
  Then it emits no type-intent evidence
  And it emits QUALITY_UNKNOWN_TEST_ORACLE rather than asserting that the test is hollow

Scenario: Shadowed or disabled type assertion is not credited
  Given TYPE_CREDIT_REJECTION applies because import provenance is shadowed, the rule is disabled, or a suppression applies
  When the scanner evaluates the call
  Then it rejects type-intent credit
  And it retains the hollow-test candidate for independent source-bound oracle classification

Scenario: Checker run status requires matching evidence
  Given no current matching EXECUTION_RECEIPT exists
  When the scan reports the test
  Then checker execution remains NOT_VERIFIED
```

## SHOULD - Technical/structural
- ADR references: none; bounded extension of existing static type configuration and test-oracle attribution.
- Data model: `selection=selected`, `selection=excluded`, `selection=unknown`, `canonical_import=true`, `canonical_import=false`, `rule_enabled=true`, `rule_enabled=false`, `ignore_state=clean`, `ignore_state=ignored`, `suppression_state=absent`, `suppression_state=present`, `checker_receipt=current_pass`, `checker_receipt=absent_or_stale`.
- API contract: existing scanner result/context schema only; no new module or public API.
- Oracle-context cache identity shall include the current code object for semantic helper functions so in-place helper-code replacement invalidates projected context.

## SHOULD NOT - Implementation details
- No blanket test-file exemption, checker execution claim, broad ty guarantee, or suppression of unrelated findings.
- Unknown or stale config, ignore, rule, source, or binding inputs must not produce an attribution cache hit.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | `selection=selected` and `canonical_import=true` and `rule_enabled=true` and `ignore_state=clean` and `suppression_state=absent` | Emit type-intent evidence; record `NOT_VERIFIED` absent `checker_receipt=current_pass` |
| 2 | `selection=excluded` or `ignore_state=ignored` or `rule_enabled=false` or `suppression_state=present` or `canonical_import=false` | Reject type-intent credit; independently classify runtime-oracle evidence as proven hollow or unknown |
| 3 | `selection=unknown` or provider/binding provenance is ambiguous | Emit no type-intent evidence; retain the hollow-test candidate; classify concrete QUALITY_HOLLOW_TEST only with a source proof of no runtime oracle |
| 4 | `checker_receipt=current_pass` | Record verified execution only for its matching candidate/config/checker identity |
