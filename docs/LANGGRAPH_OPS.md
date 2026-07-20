# Receipt-Backed Mission Graph Operations

Code Factory now provides a durable state machine for Product Missions. Its
SQLite event ledger is authoritative; the optional LangGraph adapter calls the
same guarded transition function and adds checkpoint/resume interoperability.
Framework checkpoints never substitute for Code Factory receipts.

## Local operation

```bash
factory langgraph doctor --json
factory langgraph init .factory/products/example/missions/M-001/mission.json --root . --json
factory langgraph status .factory/products/example/missions/M-001/mission.json --root . --json
factory langgraph history .factory/products/example/missions/M-001/mission.json --root . --json
factory langgraph verify .factory/products/example/missions/M-001/mission.json --root . --json
factory langgraph export .factory/products/example/missions/M-001/mission.json --root . --json
```

`factory langgraph event` records a named event only when its source state,
role, actor identity, idempotency key, local receipt, mission binding, and hard
budget permit it. Sensitive payload field names are rejected. Creator and
validator identities must differ. Retry clears worker identities so a fresh
context can be assigned.

Human review is first class: `pause`, `plan_revised`, and `resume` bind local
review receipts into the event chain. Release is a separate requested/decided
boundary and grants no merge, deploy, publish, connector, credential, or
external-message authority.

## Adapter boundary

Install the optional runtime with `pip install "code-factory[langgraph]"`.
`build_langgraph_adapter()` defaults to a local SQLite checkpointer and also
accepts an injected LangGraph checkpointer. Every node delegates to
`apply_mission_event`; direct writes to the Code Factory graph database remain
unsupported.

For hosted operation, use a production-grade checkpointer supplied by the
hosted runtime while retaining the Code Factory ledger and receipts as the
verification source of truth.
