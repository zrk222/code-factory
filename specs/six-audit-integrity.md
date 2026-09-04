# Spec: Six audit integrity
Status: implementation requested
## MUST - Functional core
### Requirements (EARS)
- When `REQ_JOIN` receives execution evidence, it shall reject duplicate, unknown, malformed or kind-mismatched execution entries before evaluating any lane. Missing lanes shall retain the existing incomplete result.
- When `REQ_GUIDANCE` returns lane results, it shall distinguish evidence repair from application repair, include both signed target and negative replay commands, and retain zero execution authority.
## Acceptance
```gherkin
Scenario: Ambiguous evidence
 Given REQ_JOIN receives duplicate execution identities
 When REQ_JOIN indexes evidence
 Then REQ_JOIN rejects the collection
Scenario: Actionable repair
 Given REQ_GUIDANCE receives an incomplete lane
 When REQ_GUIDANCE returns repair steps
 Then REQ_GUIDANCE routes evidence repair without executing commands
```
## SHOULD - Structural
- At most 6 execution entries, matching the existing six signed lanes.
- Replay commands remain suggestions for supervised execution, not approval.
