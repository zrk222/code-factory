# Spec: ProofLab
Status: approved

## MUST - Functional core
### Description
Processes proof decisions for the `Maintainer` role.

### User roles
- Maintainer

### Requirements (EARS)
- When a `PROOF_REQUESTED` event arrives, the system shall store `PROOF_REQUESTED`.
- When a proof has more than `0` failures, the system shall return `BLOCKED`.
- The system shall store each verified proof in the `passports` table.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: proof validation
  Given a `PROOF_REQUESTED` event
  When a proof has more than 0 failures
  Then the system returns BLOCKED and writes `passports`
```

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | `PROOF_REQUESTED` | store `PROOF_REQUESTED` |
| 2 | failures exceed `0` | return `BLOCKED` |
| 3 | `passports` | write `passports` |
