# ADR — Reserve cost before provider work

## Decision

Agent Cloud will use atomic Convex mutations to reserve estimated model-call cost before any future provider adapter may run. The calculation includes the run's settled cost and all outstanding reservations. Reconciliation cannot exceed the reserved amount; unused reservations are explicitly released. A caller-provided idempotency key prevents replay from consuming budget twice.

## Why

A UI estimate is not a hard limit. Concurrent calls can independently observe the same remaining amount unless admission and ledger update occur in one transaction. Convex mutations serialize conflicting reads and writes, making the ceiling executable and adversarially testable.

## Consequences

This alpha proves ledger behavior only. Provider estimates must eventually be conservative, and real provider adapters must reserve before network access. Over-estimate reconciliation releases unused commitment; an unexpectedly higher actual charge fails closed for investigation rather than silently raising the budget.
