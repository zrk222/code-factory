# Atomic Proof Adapter

Code Factory can verify four useful workflow mechanics from a local Atomic
export without becoming another agent runtime:

1. A typed, explicitly declared acyclic stage DAG.
2. Capability- and scope-bound handoffs between declared stages.
3. Checkpoint continuity that can resume only through a new,
   human-reviewed fork with unchanged evidence bindings.
4. Immutable artifact, tool-manifest, and source-precondition hashes.

This is an evidence adapter, not a replacement for Atomic. It borrows the
mechanics of explicit workflow graphs and durable handoffs while keeping Code
Factory in its independent verifier role. It has no Atomic package dependency.

## Boundary first

The adapter accepts a small, secret-free JSON envelope. It rejects unknown
fields, prompt or tool-output bodies, credentials, source bodies, network URLs,
parent-traversal paths, non-canonical JSON, and inputs over 1 MiB before writing
an output.

It never:

- imports or invokes Atomic;
- starts a stage, sends an intercom message, or resumes a checkpoint;
- reads a credential, calls a provider, changes source, or repairs work;
- authenticates the declared agent or proves that its runtime actually ran;
- treats a declared worktree, container, VM, or remote host as sandbox proof;
- approves, merges, publishes, deploys, signs, or releases anything.

The adapter only writes an immutable local receipt after the envelope's Oracle
Contract is current and exact. Its authority flags are always false.

## The binding chain

```text
sealed Oracle Contract
  -> explicit typed DAG
  -> stage scope + capabilities + source preconditions
  -> scoped handoff hashes
  -> checkpoint continuity
  -> immutable local adapter receipt
  -> read-only Graph Ops / MCP / WebMCP inspection
```

Each stage must match exactly one declared workflow node. Every source
precondition and handoff scope must remain inside the sealed Oracle Contract
scope. A handoff must name an edge in the DAG and match its sender's capability,
source-precondition hash, artifact hash, tool-manifest hash, and contract hash.

| Condition | Result | Receipt write |
| --- | --- | --- |
| Unknown, private, oversized, or path-escaping input | `E_ATOMIC_ENVELOPE_SCHEMA`, `E_ATOMIC_PRIVATE_FIELD`, or `ATOMIC_INPUT_REJECTED` | No |
| Missing stage/hash or cyclic/unknown topology | `E_ATOMIC_EVIDENCE_UNVERIFIED` | No |
| Stage or precondition outside Oracle scope | `E_ATOMIC_SCOPE_ESCAPE` | No |
| Missing/stale/mismatched Oracle Contract | `E_ATOMIC_UNBOUND_INTENT` | No |
| A handoff differs from the declared sender or a prior same-ID handoff | `E_ATOMIC_HANDOFF_DRIFT` | No |
| Resume differs in workflow, contract, checkpoint, tool manifest, or source preconditions | `E_ATOMIC_RESUME_DIVERGENCE` | No; use `human_reviewed_fork` |
| Exact evidence binding | `ATOMIC_RUN_BOUND` | Yes, once |

## Operator flow

1. Capture the original request and seal an Oracle Contract before agent work.
2. Have a team-owned exporter produce a bounded
   `factory.atomic-run-envelope.v1` JSON file containing only identifiers,
   hashes, scope paths, stage facts, handoff facts, and checkpoint facts.
3. Import the export locally.
4. Inspect Graph Ops or status tools. Separately decide whether any work should
   run, resume, merge, or release.

```powershell
factory atomic import `
  --root . `
  --envelope .factory\exports\atomic-run.json `
  --json

factory atomic verify .factory\atomic\<receipt>.json --root . --json
factory atomic status --root . --json
factory graph ops --root . --json
```

Existing receipt paths are immutable: choose a new output path or run ID when
importing a successor. A resume always has a different run ID and must retain
the same approved workflow, contract, checkpoint hash, tool manifest, and
source-precondition list. Its local receipt labels recovery as
`human_reviewed_fork`; that label is not an authorization to resume anything.

## Read-only assistant access

MCP and WebMCP expose `factory.atomic_status`. The payload carries
`ATOMIC_MCP_READ_ONLY` and every authority flag remains false. It can help an
assistant explain what the local evidence says, but it cannot operate the
workflow or alter a contract.

## What this adds beyond a green run

A completed stage is not enough. The adapter makes these questions explicit:

- Was the stage part of the declared DAG, or merely named in an export?
- Did a handoff cross both stages' approved capability and path scope?
- Did the source snapshot, artifact, or tools change between handoff and review?
- Is a proposed resume still tied to the exact intent and checkpoint?

Those facts improve senior-review visibility. They do not prove implementation
correctness, production behavior, or any vendor's runtime identity.
