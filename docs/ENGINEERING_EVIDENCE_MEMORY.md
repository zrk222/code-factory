# Engineering Evidence Memory and module handoffs

Keep useful engineering lessons without treating yesterday's green result as today's permission.
This feature reuses the local Continuity ledger; it does not create a second memory database.

## What happens

1. A writer records metadata with evidence references shaped as `sha256:DIGEST:relative/path`.
2. A different declared promoter reviews and promotes the record using `factory continuity promote`.
3. Recall selects the exact tenant, purpose and scope, checks the audit chain, record digest,
   expiry and actual evidence files. Invalid records are excluded without exposing their summaries.
4. A receiving assembly module repeats those checks before using a handoff. Changed evidence,
   withdrawal or a wrong route invalidates the packet. Nothing executes automatically.

```sh
factory evidence-memory --root . --tenant team --subject reviewer --purpose delivery-review@1 --scope repo:example
factory evidence-memory --root . --tenant team --subject reviewer --purpose delivery-review@1 --scope repo:example --sender specline --receiver forgeline
factory evidence-memory --root . --tenant team --subject reviewer --purpose delivery-review@1 --scope repo:example --sender specline --receiver forgeline --accept handoff.json
factory continuity withdraw --help
```

Save the second command's JSON output as `handoff.json` inside the workspace to use the third.
Both sides explicitly name the expected sender and receiver. Registered assembly routes currently
use `specline`, `forgeline`, `hsf`, and `prestige`; this does not claim integration into every module runner.
Python callers can use `create_knowledge_handoff` and `receive_knowledge_handoff` with the same scope.

## Focused recall without repeated corpus work

Use repeated explicit topics to reserve context for different parts of a task:

```sh
factory evidence-memory --root . --tenant team --subject reviewer --purpose delivery-review@1 --scope repo:example --query "tenant cache" --query "migration rollback" --limit 5
```

Each topic gets its next distinct matching record before another round. The
receipt distinguishes missing lexical matches from matches lost to the result
budget. Raw queries are not emitted; query hashes are not secrecy guarantees.
Handoffs still revalidate the full scope and cannot silently narrow it.

WizeMe's Memory Spine informed trust-first allocation and shared candidate
preparation. CF now tokenizes the admitted corpus once per request, shares
document frequencies/length statistics and uses the same BM25/BM25F scorer for
single and multi-topic searches. No new module, dependency, database, model,
persisted index or cross-request trust cache was added. This removes redundant
work without skipping evidence, withdrawal, expiry, scope or audit-chain checks.

Measured on Python 3.11.9/Windows with 1,000 frozen synthetic metadata records
and 11 alternating baseline/candidate pairs, complete selection medians were
46.4315 → 20.9720 ms for four topics and 95.0880 → 34.5001 ms for eight; the
candidate won all 11 pairs in each case. Scores, ordering, gaps and complete
receipt digests matched exactly. Eight-topic tokenization fell from 64,008 to
8,008 calls. A separate actual API experiment with 100 promoted fixture records,
real files and SQLite verification preserved outputs and database bytes, but
showed **no reliable end-to-end speed improvement** (5/11 paired wins).
Raw observations and source hashes are in
[the retrieval experiment](evidence/recall-preparation-20261122.json).
These are exposed retrieval experiments, not held-out defect-recall or scan
accuracy results. No universal speedup or broader detection claim follows.

Research favors compact targeted context over indiscriminate retrieval:
[Aider's repository map](https://aider.chat/docs/repomap.html) and
[Repoformer's selective-retrieval study](https://arxiv.org/html/2403.10059v2).
These informed the bounded approach, not transplanted performance claims.
[SQLite FTS5](https://www.sqlite.org/fts5.html) was evaluated, but adding a
persisted index would introduce synchronization work and would not preserve CF's
existing BM25F formula automatically. It is not part of this change.

## Controls and useful results

- Supersede a record with an independently promoted exact-scope replacement, contradict it, or revoke it.
  Withdrawal requires promoter authority, rejects the creator, and updates status and audit atomically.
- Read the influence edges to see which evidence digest supports each recalled record digest.
- Packets deduplicate evidence digests and omit raw files and summaries. Fresh receiver recall supplies
  current references; no persistent verification cache is trusted.
- Empty recall is a successful empty query, **not** an audit pass. All results have `authority: none`.
- Each operation returns a brief action summary. Failures return blocked state and a machine-readable code.

## Limits and security boundary

Local principal names are declarations, not authenticated identities. The ledger and packets are
unsigned: hashes detect inconsistent content but cannot stop an attacker rewriting the entire ledger
and its hash chain. Integrators must supply authenticated authorization and protected storage.
Summary text is untrusted reference data, never an instruction, policy, or approval.
File checks establish byte consistency at read time, not truth or a lasting file lock.
The store must already exist. Recall is read-only, bounded to 1000 selected records and 10000 tenant
audit events; overflow blocks. Individual evidence files use the existing 10 MB read bound.
This is a local exchange API/CLI, not a network transport, authenticated agent protocol, or automatic release gate.
