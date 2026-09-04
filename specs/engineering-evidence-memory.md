# Spec: Engineering Evidence Memory
Status: approved for implementation under user request

## MUST - Functional core
### Requirements (EARS)
- When `REQ_HANDOFF` transfers knowledge between registered assembly modules, it shall emit a versioned digest-only packet and require the receiver to repeat exact-scope recall; altered, misrouted or stale packets shall block without execution authority. [R5]
- When `REQ_SCOPE` recalls memory, it shall require exact tenant, purpose and repository scope authorization, use 1 read-only SQLite snapshot, and inspect at most 1000 records; overflow shall block. [R1]
- When `REQ_EVIDENCE` admits a record, it shall require independent promotion, non-expiry, a valid content digest, and 1 or more local SHA-256-bound evidence references; missing, changed or malformed evidence shall exclude the record. [R2]
- When `REQ_WITHDRAW` changes a verified record, it shall require promoter authorization, prohibit its creator from withdrawing it, and atomically record status superseded, contradicted or revoked with 1 audit event; supersession shall require a verified replacement with exact matching tenant, purpose and scope. [R3]
- When `REQ_INFLUENCE` returns recall, it shall include record and evidence digests, exclusions without summary text, a deterministic influence digest and zero approval or execution authority. [R4]

### Acceptance criteria
```gherkin
Scenario: Receiver revalidates knowledge
 Given REQ_HANDOFF emits a packet before evidence changes
 When REQ_HANDOFF receives the packet after evidence changes
 Then REQ_HANDOFF blocks the stale packet
Scenario: Scope and evidence govern recall
 Given REQ_SCOPE selects an exact authorized scope with 1 promoted record
 When REQ_EVIDENCE finds changed evidence
 Then REQ_INFLUENCE excludes the summary and returns zero approval authority
Scenario: Independent withdrawal
 Given REQ_WITHDRAW receives 1 creator request to revoke a record
 When REQ_WITHDRAW authorizes the request
 Then REQ_WITHDRAW rejects self withdrawal
Scenario: Bounded snapshot
 Given REQ_SCOPE encounters more than 1000 records
 When REQ_SCOPE reads the snapshot
 Then REQ_SCOPE blocks the recall
```

## SHOULD - Structural
- Reuse ContinuityStore, its role authorization and transaction/audit boundary.
- Evidence references consist of sha256, a 64-character lowercase hex digest and a canonical workspace path, separated by colons.
- Parse the reference using at most 2 colon splits to preserve the path component for canonical path validation.
- Read at most 1001 rows to detect overflow. Use existing 10,000,000-byte file bound.
- Verify at most 10000 tenant audit events in the same snapshot, probing 10001 for overflow. Require the latest event to match promotion before recall.
- Local principal strings and unsigned hashes do not authenticate people or prove truth.
- Recalled summaries are untrusted data, never instructions or approved gate changes.
- No embedding, hosted service, neural model, automatic promotion or release action.
