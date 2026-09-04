# Spec: Audit observation consistency
Status: implementation requested
## MUST - Functional core
### Requirements (EARS)
- When `REQ_STATEFUL` evaluates counters, it shall reject action totals above examples multiplied by max_actions, violations above checks, and failure traces longer than the observed max_actions as incomplete evidence.
- When `REQ_RECOVERY` evaluates concurrency, it shall reject a max_concurrency greater than the number of observed operations as incomplete evidence.
### Acceptance criteria
```gherkin
Scenario: Impossible observation
 Given REQ_STATEFUL receives action totals exceeding the generation bound
 When REQ_STATEFUL evaluates the observation
 Then REQ_STATEFUL returns incomplete rather than pass
Scenario: Impossible concurrency
 Given REQ_RECOVERY receives more simultaneous operations than recorded operations
 When REQ_RECOVERY evaluates the observation
 Then REQ_RECOVERY returns incomplete rather than pass
```
## SHOULD - Structural
- Retain existing schemas, signed policy thresholds and known-bad controls.
- Equality at each bound is valid; this is consistency checking, not exhaustive proof.
- Preserve existing parser bounds: examples 2..1000, actions 2..200, seed 0..4294967295, identifiers 1..128, counters 0..1000000, action counts 0..200000, fault modes 1..32, concurrency 1..64, operator length 8. These are unchanged structural bounds, not new business thresholds.
