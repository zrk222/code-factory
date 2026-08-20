# Spec: factory-continuity-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Factory Continuity is a local, metadata-only engineering-memory ledger. It
answers whether a prior decision may influence one new delivery decision. It
does not store memory content, rank retrieval, call a model, authenticate an
identity, provide key management, erase data, anchor evidence externally, or
grant release authority.

### User roles

- Writer supplies one opaque memory reference plus exact scope, purpose,
  expiry, and declared evidence references.
- Independent promoter reviews and promotes an evidenced draft.
- Reader recalls only current records for an exact scope and exact purpose.

### Requirements (EARS)

- When a continuity record omits schema `factory.continuity.record.v1`, tenant, record type, opaque memory reference, purpose identifier/version, repository scope, one through 24 evidence references, future RFC3339 expiry, or an idempotency key of at most 160 characters, the system shall reject the request before writing a record or audit event.
- When a continuity record contains a top-level `content`, `payload`, `embedding`, `text`, `messages`, or `vector` field, the system shall return `E_CONTENT_STORE_FORBIDDEN` and shall not store the memory body.
- When a writer records a valid continuity record, the system shall atomically write one draft record and one tenant hash-chain audit event, or write neither.
- When the same tenant retries an idempotency key with byte-equivalent normalized metadata, the system shall return the original immutable record; if any normalized metadata differs, it shall return `E_IDEMPOTENCY_CONFLICT`.
- When a promoter differs from the record writer, has the exact tenant and purpose grant, the record has evidence, the record expiry is at least 1 microsecond after the server UTC promotion time, and the record remains draft, the system shall promote the record to `verified` and append one audit event.
- If a record writer attempts promotion, a promoter has another tenant or purpose, a record expiry is at most 0 microseconds after the server UTC promotion time, or a record is no longer draft, the system shall reject promotion before changing the record.
- When a reader requests recall with an exact tenant, purpose, and repository scope, the system shall return only independently promoted records with expiry at least 1 microsecond after the server UTC recall time that exactly match all three values and shall list matching expired record IDs as withheld.
- When a continuity audit event changes bytes, the system shall return local proof with `audit.valid` false.
- When Graph Ops reads `.factory/continuity.sqlite3`, the system shall render typed redacted continuity nodes with no memory reference or summary, return `GRAPH_OPS_CONTINUITY_METADATA_READ_ONLY`, and shall not change database bytes.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: An independently reviewed decision becomes eligible for exact reuse
  Given a writer records one evidenced decision for delivery-review@1 and repo:sha256:abc123
  When a different promoter promotes the current draft
  And a reader recalls delivery-review@1 for repo:sha256:abc123
  Then recall returns that verified record
  And the result has no write, promotion, or external-effects authority

Scenario: Historical context is not blindly reused
  Given one promoted continuity record is expired or has another purpose or scope
  When a reader requests recall for delivery-review@1 and repo:sha256:abc123
  Then recall withholds the expired record
  And it returns no record for another purpose or scope

Scenario: Graph Ops exposes metadata without becoming a memory authority
  Given a local continuity ledger contains one promoted record
  When Graph Ops compiles its snapshot
  Then it contains a redacted continuity record node
  And database bytes remain unchanged
  And the page has a disabled promotion control
```

## SHOULD - Technical and structural

- Data model: `factory.continuity.record.v1`, `factory.continuity.audit.v1`,
  `factory.continuity.proof.v1`, and `factory.continuity.v1`.
- Graph Ops shall make `expired` and `draft` records visible as withheld or
  awaiting independent review, not as reusable facts.
- Documentation shall retain the Memory Platform claim boundary: local hash chaining
  is unsigned and is not hosted identity, KMS, erasure, external anchoring, or
  compliance proof.

## SHOULD NOT - Implementation details

- The feature should not store source, memory bodies, vectors, embeddings, or
  conversation transcripts; call a model; create a network service; self-promote
  an agent record; sign, publish, deploy, merge, send a message, or access a
  credential.
