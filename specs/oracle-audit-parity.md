# Spec: Oracle audit parity
Status: implementation requested
## MUST - Functional core
### Requirements (EARS)
- When `REQ_PARITY` verifies an Oracle contract, it shall validate all rule groups using the existing constructor validators and reject missing authoritative rules even if the local digest matches.
- When `REQ_SOURCE` verifies sources, it shall reject empty sources, duplicate identifiers and missing original-intent binding.
- When `REQ_CAPTURE` reconciles capture files, it shall require the integrity receipt to match a fresh validation of its original candidate and contract sources before producing an output receipt.
### Acceptance criteria
```gherkin
Scenario: Rehashed weakening
 Given REQ_PARITY reads a rehashed contract with empty gates
 When REQ_PARITY verifies the contract
 Then REQ_PARITY rejects the contract
Scenario: Lost intent binding
 Given REQ_SOURCE reads a rehashed contract with no sources
 When REQ_SOURCE verifies sources
 Then REQ_SOURCE rejects the contract
Scenario: Removed screenshot requirements
 Given REQ_CAPTURE reads a rehashed receipt with removed requirements
 When REQ_CAPTURE reconciles capture evidence
 Then REQ_CAPTURE rejects the receipt
```
## SHOULD - Structural
- Reuse existing authority origins, rule-group limits and source schema. No new authority or signer claims.
