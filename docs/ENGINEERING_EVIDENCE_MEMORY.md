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
