# Code Factory 0.45.4 — verify the agent workflow, not just its final claim

An agent can hand over a green result while hiding the path that produced it.
This update makes that path inspectable without letting the workflow grade
itself.

## What changed

- `factory atomic import` accepts a compact, secret-free workflow envelope and
  verifies its typed acyclic stage graph, capabilities, scoped handoffs,
  checkpoints, source-byte preconditions, and resume lineage.
- Every accepted run is bound to the current sealed Oracle Contract. Changed
  intent, source bytes, topology, tools, checkpoints, or handoff facts fail
  closed rather than becoming a new normal.
- Graph Ops shows the contract-to-stage-to-handoff proof chain and offers a
  copy-only control for the exact local receipt verification command.
- Local MCP and WebMCP expose the same bounded status to compatible AI coding
  assistants without adding execution authority.

## Why it matters

Solo developers can see whether a multi-step agent run stayed inside the
agreed task. Teams get a durable handoff and resume record instead of a prompt
transcript. Senior reviewers can inspect where scope, source, or checkpoint
drift first appeared before deciding whether the result may proceed.

## Authority boundary

Code Factory does not start Atomic, execute a stage, send an intercom message,
resume a checkpoint, prove a declared sandbox, approve a change, apply a
repair, merge, publish, or deploy. The imported workflow is evidence. Human
approval and independently enforced runtime controls remain separate.

## Start

```powershell
pip install factoryline-code-factory==0.45.4
factory atomic import --root . --envelope .factory/atomic/run-envelope.json --json
factory atomic status --root . --json
factory graph ops --root .
```

See [Atomic Proof Adapter](ATOMIC_PROOF_ADAPTER.md) for the exact envelope,
failure markers, and verification commands.
