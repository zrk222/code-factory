# Spec: Oracle projection integrity
## MUST - Functional core
### Requirements (EARS)
- When `REQ_SHAPE` projects authority receipts, it shall reject non-object JSON and oversized inputs above 1048576 bytes as invalid without aborting the snapshot.
- When `REQ_FRESH` projects a ready receipt, it shall reject inequality with a fresh validation of the original authority source and sealed contract before counting it as current.
### Acceptance criteria
```gherkin
Scenario: Malformed input
 Given REQ_SHAPE reads a JSON list
 When REQ_SHAPE projects status
 Then REQ_SHAPE counts the input as invalid
Scenario: Changed authority
 Given REQ_FRESH reads a ready receipt whose authority source changed
 When REQ_FRESH projects status
 Then REQ_FRESH counts the input as invalid
```
## SHOULD - Structural
- Preserve public function signatures, receipt format and existing gate checks. Extract validation helpers to reduce complexity without changing authority semantics. Scan at most 100 local receipts. UTF-8 encoding and existing 160 character reviewer bounds remain unchanged. No provider access or output writes during projection.
- Existing baseline bounds remain 500 characters for generic text and 200 characters per candidate field, with 2-space JSON indentation. These values predate this repair; no threshold is widened.
