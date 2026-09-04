# Spec: Module audit readiness
Status: implementation requested
## MUST - Functional core
### Requirements (EARS)
- When `REQ_PROOF` verifies reusable proof rows, it shall reject non-object rows as invalid evidence without crashing the verifier.
- When `REQ_RECEIPT` displays runtime readiness, it shall require exactly 6 distinct recognized lane kinds and distinct nonempty lane IDs, recognized lane states, no release authority, and a decision matching the lane states; contradictions shall return incomplete.
- When `REQ_SCOPE` records the module audit, it shall emit 3 categories: reviewed files, repaired findings and unverified modules.
### Acceptance criteria
```gherkin
Scenario: Malformed proof row
 Given REQ_PROOF receives a non-object artifact row
 When REQ_PROOF verifies reuse
 Then REQ_PROOF returns invalid evidence
Scenario: False green receipt
 Given REQ_RECEIPT reads a self-hashed receipt with no lane results
 When REQ_RECEIPT displays readiness
 Then REQ_RECEIPT returns incomplete
Scenario: Honest coverage
 Given REQ_SCOPE records reviewed runtime modules
 When REQ_SCOPE records external module engines
 Then REQ_SCOPE labels unaudited engines unverified
```
## SHOULD - Structural
- Receipt self-hashes provide consistency only, not authentication or current candidate validation.
- States remain PASS, FAIL, INCOMPLETE; decisions remain BLOCKED and READY_FOR_HUMAN_REVIEW.
