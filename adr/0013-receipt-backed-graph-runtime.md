# ADR 0013: Receipts govern the stateful graph runtime

## Status

Accepted.

## Decision

Code Factory will provide a durable stateful runtime for Product Missions. A
transactional SQLite event store is the canonical runtime record. Every state
transition is validated against the mission, actor role, bounded budget, and a
hash-bound local receipt before it is committed to a previous-hash event chain.

LangGraph is an optional execution adapter. It may provide checkpointing,
interrupt/resume behavior, streaming, and integration with LangGraph operator
tools. It does not validate Code Factory evidence, grant authority, or replace
the canonical event chain. Native operation remains available without any
LangGraph or LangSmith dependency.

## Consequences

- Long-running missions can resume after process failure without losing their verified position.
- Operators can inspect state, history, topology, attempts, and the next allowed events.
- Duplicate delivery is safe through event-bound idempotency keys.
- Worker, validator, owner, and release authority remain distinct.
- LangGraph teams get a supported adapter without forcing the dependency on local users.
- Replaying a framework checkpoint cannot replay or authorize external effects.
