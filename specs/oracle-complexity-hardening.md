# Spec: Oracle complexity hardening

## MUST - Functional and security boundaries

### Requirements (EARS)

- When `REQ_METADATA_READ_BOUND` reads a selected metadata file, it shall enforce a maximum of 1048576 bytes both before and after reading and shall return an oversize file entry without parsing it.
- If `REQ_METADATA_EXPLICIT_EMPTY` receives an explicitly empty path list, it shall reject the request as missing input rather than discover default paths.
- When `REQ_METADATA_PARITY` audits an unchanged supported input, it shall return the existing file entries, findings, markers, status, authority and digest schema unchanged.
- When `REQ_ORACLE_PLAN_BINDING` validates a challenge plan, it shall reconstruct the complete expected critical-case set from the currently verified contract and reject every missing, extra, reordered, duplicated or altered case.
- If `REQ_ORACLE_RESULT_SHAPE` receives a malformed, duplicated, missing or extra result case, it shall return marker `ORACLE_CHALLENGE_FAILED` and shall not report the challenge as verified.
- When `REQ_ORACLE_INCIDENT_BINDING` records a demotion incident, it shall independently re-run the referenced current prior-to-candidate contract comparison and require the supplied drift digest to equal that reconstructed blocked semantic-weakening receipt.
- When `REQ_COMPLEXITY_BOUND` inspects `audit_metadata`, `seal_oracle_contract`, `compile_oracle_challenge`, `validate_oracle_challenge_plan`, `verify_oracle_challenge_result` and `record_oracle_incident`, it shall return `complexity_pass=true` only when every named function contains 10 or fewer decision branches.
- While `REQ_AUTHORITY_BOUNDARY` evaluates this slice, it shall grant no execution, approval, repair, merge, publication, deployment, signing, messaging, credential or connector authority.

### Acceptance criteria

```gherkin
Scenario: Post-read growth cannot bypass the metadata byte bound
  Given REQ_METADATA_READ_BOUND receives bytes larger than 1048576 after its initial size observation
  When the metadata audit handles the bytes
  Then REQ_METADATA_READ_BOUND records an oversize file and does not parse its content

Scenario: Explicit empty input does not trigger discovery
  Given REQ_METADATA_EXPLICIT_EMPTY receives an explicitly empty path list
  When the metadata audit selects its inventory
  Then REQ_METADATA_EXPLICIT_EMPTY rejects the request as missing input

Scenario: Existing metadata receipts retain their contract
  Given REQ_METADATA_PARITY receives an unchanged supported metadata fixture
  When the metadata audit returns its receipt
  Then REQ_METADATA_PARITY returns the existing entries findings markers status authority and digest schema

Scenario: Challenge plan is derived from the sealed contract
  Given REQ_ORACLE_PLAN_BINDING receives a hash-valid plan with one changed case
  When the plan is validated against the current contract
  Then REQ_ORACLE_PLAN_BINDING rejects the plan

Scenario: Duplicate result rows do not collapse into a passing map
  Given REQ_ORACLE_RESULT_SHAPE receives all expected cases plus one duplicate
  When the challenge result is verified
  Then REQ_ORACLE_RESULT_SHAPE returns ORACLE_CHALLENGE_FAILED

Scenario: A fabricated local drift cannot demote an agent
  Given REQ_ORACLE_INCIDENT_BINDING receives a self-hashed blocked drift that was not reconstructed from its bound contracts
  When an incident is requested
  Then REQ_ORACLE_INCIDENT_BINDING rejects the request before writing an incident

Scenario: Public coordinators stay bounded
  Given REQ_COMPLEXITY_BOUND inspects the six named functions
  When strict Forge QA runs with complexity limit 10
  Then REQ_COMPLEXITY_BOUND passes every named function

Scenario: The hardening slice grants no operational authority
  Given REQ_AUTHORITY_BOUNDARY evaluates a metadata Oracle plan result or incident receipt
  When the receipt is returned
  Then REQ_AUTHORITY_BOUNDARY returns every operational authority field as false
```

## SHOULD - Structural

- Extract deterministic parsing, contract normalization, challenge construction and incident validation helpers. Preserve public signatures and existing receipt schemas.

## Non-goals

- No provider calls, external identity proof, sandbox claim, deployment, publication or release approval.
- No threshold increase, exception, scanner suppression or compatibility break.
