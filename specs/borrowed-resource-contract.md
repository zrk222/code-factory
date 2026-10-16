# Spec: borrowed-resource-contract
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
The empty-implementation audit distinguishes a documented caller-owned resource
wrapper from an unfinished production method, without suppressing unrelated
empty implementations.

### User roles
- FactoryLine maintainers reviewing implementation-completeness findings.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- When `borrowed_owner_contract` is true, the system shall emit no quality finding for the intentional no-op wrapper.
- When `resource_wrapper_shape` is false, the system shall emit the quality finding for the wrapper.
- If `source_name_integrity` is false, the system shall emit the quality finding for the wrapper.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Explicit borrowed-resource wrapper contract is exempted
  Given `borrowed_owner_contract` is true for the retained `_KeepOpenFile` shape
  When the implementation-completeness audit inspects `__exit__`
  Then it emits no empty-implementation finding for that method

Scenario: Generic renamed wrapper variants are exempted
  Given two wrappers with different names and explicit equivalent contracts
  When each stores a constructor argument, returns self from `__enter__`, and delegates the same field through `__getattr__`
  Then each direct contract call returns true

Scenario: Lookalike or unfinished wrappers remain findings
  Given `resource_wrapper_shape` is false for a bare pass, decorated/duplicate method, non-self enter, missing/mismatched field, or shadowed/rebound `getattr`
  When the implementation-completeness audit inspects `__exit__`
  Then the empty-implementation finding remains

Scenario: Contradictory or unfinished owner documentation remains a finding
  Given `source_name_integrity` is false when owner documentation contradicts the no-close contract or contains unfinished text
  When the implementation-completeness audit inspects `__exit__`
  Then the empty-implementation finding remains

Scenario: Genuine unfinished methods remain findings
  Given an undocumented pass, ellipsis, or undocumented NotImplementedError body
  When the implementation-completeness audit runs
  Then the existing unfinished-method finding remains

Scenario: Python file inventory stays at its ceiling
  Given the new implementation audit module is pinned to 800 lines and 32,000 bytes
  When the architecture policy is evaluated
  Then all previous file caps remain byte-for-byte equal and the total Python budget remains 460
```

## SHOULD — Technical/structural
- ADR references: none; bounded extraction under existing architecture policy.
- AST-only local source contracts; do not import or execute scanned project code. The no-op contract inspects `__exit__`, `__enter__`, `__init__`, `__getattr__`, built-in `getattr`, and documented `_KeepOpenFile` source shape. The unfinished-method controls include `NotImplementedError`.
- API contract: preserve public `intent_quality` imports and signatures through explicit compatibility re-exports.
- Architecture limits: new module <=800 lines and <=32000 bytes; keep all existing caps, `max_python_files=460`, and `max_core_modules=129` unchanged.
- Test inventory: preserve all three privacy test functions and assertions when moving them into `tests/test_compliance.py`; remove `tests/test_privacy.py`.

## SHOULD NOT — Implementation details
<!-- Leave the "how" to the plan/tasks unless it is a systemic invariant -->

## Decision logic (factory candidates)
<!-- Ordered business rules over extracted facts. specline handoff compiles
     these via HSF instead of letting agents improvise them. -->
| # | if | then |
|---|----|------|
| 1 | `borrowed_owner_contract` and `resource_wrapper_shape` are true | Emit no empty-implementation finding for that method |
| 2 | `resource_wrapper_shape` is false, or `source_name_integrity` is false | Keep the empty-implementation finding |
