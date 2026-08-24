# Factory Continuity

Factory Continuity is a local, proof-carrying **engineering-memory metadata**
ledger. It helps a developer or agent answer one narrow question safely:

> Is this prior decision eligible to influence this exact delivery decision?

It is not a vector database, embedding service, memory-content store, hosted
identity provider, KMS, retention service, or compliance product. It never
stores `content`, `payload`, `embedding`, `text`, `messages`, or vectors. A
record contains an opaque memory reference plus scope, purpose, expiry, and
evidence references.

## Why it exists

An agent can find an old decision, failed approach, exception, or incident
lesson. That does not make it current or authorized. Factory Continuity makes
the missing checks explicit:

- **Exact scope:** a record applies only to its opaque repository scope.
- **Exact purpose:** a caller needs the declared purpose and version.
- **Independent promotion:** a writer cannot promote their own record.
- **Evidence:** a promoted record has declared evidence references.
- **Expiry:** expired records are withheld, not silently reused.

The local ledger makes record and audit event one SQLite transaction. Recall is
read-only. Its hash chain is local and unsigned; do not represent it as an
external anchor, signing guarantee, authenticated identity system, erasure
mechanism, or compliance evidence.

## Use it

```powershell
factory continuity init --db .factory/continuity.sqlite3

factory continuity record continuity-record.json `
  --idempotency-key adr-0042-review `
  --db .factory/continuity.sqlite3 `
  --tenant engineering `
  --subject planner-agent `
  --roles writer `
  --purposes delivery-review@1

# A different trusted principal promotes the draft after independent review.
factory continuity promote <record-id> `
  --reason "ADR and proof receipt reviewed" `
  --db .factory/continuity.sqlite3 `
  --tenant engineering `
  --subject release-owner `
  --roles promoter `
  --purposes delivery-review@1

factory continuity recall `
  --purpose delivery-review@1 `
  --scope repo:sha256:<your-workspace-scope> `
  --db .factory/continuity.sqlite3 `
  --tenant engineering `
  --subject reviewer `
  --roles reader `
  --purposes delivery-review@1
```

`--subject`, `--roles`, and `--purposes` are local reference inputs. They are
not identity authentication. A hosted adapter must authenticate the caller
before it creates a principal.

## Record contract

```json
{
  "schema": "factory.continuity.record.v1",
  "tenant_id": "engineering",
  "record_type": "decision",
  "memory_ref": "memory://engineering/adr-0042",
  "purpose": {"id": "delivery-review", "version": "1"},
  "scope": {"repository_ref": "repo:sha256:example"},
  "evidence_refs": ["receipt:sha256:abc", "adr:0042"],
  "summary": "Bounded metadata only; never a memory body.",
  "expires_at": "2027-01-01T00:00:00Z"
}
```

Allowed record types are `decision`, `constraint`, `outcome`, `lesson`, and
`exception`. Every record must be idempotency-keyed. An idempotency replay with
different content fails closed.

## Graph Ops Decision Replay lane

`factory graph ops --root . --json` projects redacted continuity metadata from
`.factory/continuity.sqlite3` when it exists. The Graph Ops Studio lane shows
only record type, purpose, scope digest, evidence digest, expiry, and promotion
state. It deliberately withholds the memory reference and summary.

The UI can copy a recall command template and validate the redaction boundary.
Its promotion button is disabled. Graph Ops cannot write content, promote a
record, sign, merge, publish, deploy, or grant an agent access.

## Gauntlet precision binding

A Gauntlet source can optionally select already verified, unexpired records for
its exact tenant, purpose, and repository scope. `factory gauntlet plan` reads
only the redacted metadata through the read-only recall boundary and embeds
hashes, record types, and evidence digests in the plan. It does not recall a
memory body or give the selected record authority to generate tests, run them,
or approve work. See [Gauntlet](GAUNTLET.md) for the source contract.

## Boundary and next service milestone

This is the local Continuity Core, not a hosted memory service. Before a hosted
or enterprise claim, the remaining independent units include authenticated
identity lifecycle, tenant isolation under the hosted store, purpose policy
mutation testing, encrypted record authority and erasure, external anchoring,
and a separate cross-language verifier. The governing plan is
[Memory Platform plan](MEMORY_PLATFORM_PRD.md); its labels must not be advanced without the
specified exit evidence.
