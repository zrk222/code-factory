# Spec: agent-cloud-memory-governance-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core

### Description

Deliver the first Phase 2 security-alpha slice inside the existing local Convex pilot: governed memory correction, content erasure, portable export, retention enforcement, and provenance history. This slice does not claim hosted multi-tenancy, OIDC, billing, or production identity because the PRD commercial gate has not been evidenced.

### Requirements (EARS)

- When an Admin writes memory, the system shall return `MEMORY_PROVENANCE_BOUND` after storing policy version `memory-policy.v1`, source, purpose, provenance, confidence, retention, and trust label `untrusted-context`.
- When an Admin corrects an active memory, the system shall return `MEMORY_CORRECTED` after creating exactly 1 successor record, marking exactly 1 predecessor superseded, and appending correction receipt and audit evidence.
- If the correction target is deleted or superseded, the system shall return `E_MEMORY_NOT_ACTIVE` before any write.
- When active memory is listed, the system shall return records where both `deletedAt` and `supersededAt` are absent.
- When an Admin erases a memory, the system shall return `MEMORY_CONTENT_ERASED` after replacing subject, content, source, purpose, and provenance with non-sensitive tombstone values and appending a deletion receipt.
- If a memory is already erased, the system shall return `E_MEMORY_ALREADY_DELETED` before any write.
- When memory is exported, the system shall return `MEMORY_EXPORT_READY`, canonical JSON, and a 16-character prototype digest after representing active, superseded, and erased records without exposing erased content.
- When canonical export runs, the system shall return `MEMORY_EXPORT_SANITIZED` after emitting exactly 0 database identifiers and exactly 0 receipt fingerprints.
- When retention enforcement runs, the system shall return `MEMORY_RETENTION_ENFORCED` after inspecting at most 1000 memory records per run, `RETENTION_EXPIRED` identifying each non-erased record where `createdAt + retentionDays * 86400000 <= server clock`, and erasing each identified record.
- When retention enforcement completes, the system shall return `RETENTION_RECEIPTS_EXACT` after appending exactly 1 deletion receipt for each newly erased record and exactly 0 receipts for records where `MEMORY_ERASED` existed before the run.
- When the memory surface renders, the system shall return `MEMORY_PROVENANCE_VISIBLE` after showing active, corrected, superseded, and erased states with source, purpose, policy version, retention, and correction lineage.
- When the memory surface renders at 390, 768, and 1440 CSS pixels, the system shall return `MEMORY_GOVERNANCE_RESPONSIVE` after exposing add, correct, erase, export, and provenance controls without horizontal overflow or overlapping actions.
- The system shall return `MEMORY_AUTHORITY_SEPARATED` after proving memory content, confidence, source, provenance, and model output grant exactly 0 action capabilities.
- The system shall return `CONVEX_ONLY_STACK` after proving exactly 1 application backend, Convex, exists in dependency and source trees.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Write governed memory
  Given the existing local Convex pilot
  When the Admin stores memory
  Then MEMORY_PROVENANCE_BOUND records memory-policy.v1 source purpose provenance confidence retention and untrusted-context
  And MEMORY_AUTHORITY_SEPARATED proves the record grants 0 action capabilities

Scenario: Correct memory without rewriting history
  Given 1 active memory governed by memory-policy.v1
  When the Admin submits corrected content and a correction reason
  Then MEMORY_CORRECTED creates exactly 1 successor
  And the predecessor is superseded and excluded from active retrieval
  And correction receipt and audit evidence identify the lineage

Scenario: Reject correction of inactive history
  Given a superseded or erased memory
  When the Admin attempts another correction against that record
  Then E_MEMORY_NOT_ACTIVE is returned and 0 records and receipts are added

Scenario: Erase personal content while retaining a tombstone
  Given an active or superseded memory containing sensitive text
  When the Admin erases it with a reason
  Then MEMORY_CONTENT_ERASED replaces subject content source purpose and provenance
  And the deletion receipt contains no erased content
  And a second erase returns E_MEMORY_ALREADY_DELETED before writes

Scenario: Export the complete governed history
  Given active superseded and erased records
  When the Admin exports memory
  Then MEMORY_EXPORT_READY returns canonical JSON with a 16-character digest
  And MEMORY_EXPORT_SANITIZED proves erased content database identifiers and receipt fingerprints are absent
  And the export records each lifecycle state and policy version

Scenario: Enforce retention exactly once
  Given 2 expired records and 1 unexpired record
  When retention enforcement runs twice
  Then RETENTION_EXPIRED identifies exactly 2 records and MEMORY_RETENTION_ENFORCED erases exactly 2 records in the first run
  And RETENTION_RECEIPTS_EXACT proves the first run appends exactly 2 deletion receipts
  And MEMORY_ERASED exists for those 2 records before the second run
  And RETENTION_RECEIPTS_EXACT proves the second run erases exactly 0 records and appends exactly 0 receipts
  And the unexpired record remains active

Scenario: Render the memory governance surface
  Given active corrected superseded and erased memory
  When browser verification renders at 390 768 and 1440 CSS pixels
  Then MEMORY_PROVENANCE_VISIBLE exposes add correct erase export and lineage controls
  And MEMORY_GOVERNANCE_RESPONSIVE proves no horizontal overflow or overlapping actions exist

Scenario: Preserve authority and backend boundaries
  Given the complete application tree
  When release verification executes
  Then memory fields grant exactly 0 capabilities
  And CONVEX_ONLY_STACK proves exactly 1 application backend
```

## SHOULD — Technical/structural

- ADR reference: `adr/agent-cloud-memory-governance-v1.md`.
- Data model: extend `memories` and receipt types in `products/agent-cloud/app/convex/schema.ts`.
- API contract: typed Convex functions in `products/agent-cloud/app/convex/memory.ts`.
- UI contract: `products/agent-cloud/app/src/components/MemoryPanel.tsx`.

### Authorized bounded constants

- Policy version is exactly `memory-policy.v1`; trust label is exactly `untrusted-context`.
- Export schema is exactly `code-factory.MemoryExport.v1`; prototype digests are exactly 16 lowercase hexadecimal characters.
- Memory content is limited to 2000 characters; subject to 200; source and purpose to 300; provenance and reasons to 500.
- Confidence is 0 through 100; retention is 1 through 3650 days; one day is 86400000 milliseconds.
- One retention enforcement run inspects at most 1000 memory records.
- Tombstones use `[erased]` for subject, source, purpose, and provenance and an empty string for content.
- Browser checks use 390, 768, and 1440 CSS pixels; primary targets are at least 44 CSS pixels high.
- Memory lifecycle controls use icon sizes 13, 14, 16, 17, 18, 20, 22, 24, and 26 CSS pixels.
- The memory authoring default uses 96 percent confidence and 365 days retention; tests may use 365 days as the unexpired control.
- The existing Phase 1 import bound remains 5000 characters and its secret-reference bound remains 240 characters.
- The existing shared shell retains icon sizes 15, 21, and 27 CSS pixels, the `PROOF LINE 01` label, and typography weights 400, 500, 600, 700, and 800.
- Test and browser commands time out after 120 seconds.

## SHOULD NOT — Implementation details

- No hosted multi-tenancy, production OIDC, SAML, SCIM, billing, or production identity claim.
- No hard deletion of audit or receipt evidence.
- No deleted content in exports, receipts, audit details, or status messages.
- No memory-derived permission, approval, capability, or credential.
- No WizeMe source, path, schema, credential, database, or asset access.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | target has `deletedAt` or `supersededAt` | reject correction with `E_MEMORY_NOT_ACTIVE` before writes |
| 2 | target has `deletedAt` | reject erase with `E_MEMORY_ALREADY_DELETED` before writes |
| 3 | `RETENTION_EXPIRED` exists and `MEMORY_ERASED` is absent | erase content and append exactly 1 deletion receipt |
| 4 | `MEMORY_ERASED` existed before retention enforcement | append 0 new deletion receipts |
| 5 | `MEMORY_ERASED` exists during export | emit tombstone state and no erased content |
| 6 | `MEMORY_AUTHORITY_SEPARATED` is absent | block release |
| 7 | `CONVEX_ONLY_STACK` is absent | block release |
| 8 | `MEMORY_PROVENANCE_BOUND` is absent after write | block memory write success |
| 9 | `MEMORY_EXPORT_SANITIZED` is absent | block memory export success |
| 10 | `MEMORY_RETENTION_ENFORCED` is absent | block retention success |
| 11 | `RETENTION_RECEIPTS_EXACT` is absent | block retention success |
| 12 | `MEMORY_PROVENANCE_VISIBLE` is absent | block UI release |
| 13 | `MEMORY_GOVERNANCE_RESPONSIVE` is absent | block UI release |
