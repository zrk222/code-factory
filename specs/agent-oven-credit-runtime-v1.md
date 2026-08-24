# Agent Oven Credit and Hosted Runtime Contract v1

## Commercial model

Agent Oven uses prepaid platform credits. Credits pay for governed platform operations, not customer-owned model inference. Every dashboard and receipt reports the two ledgers separately.

### Plan allocation

- Each paid tier grants a non-negative monthly credit allocation.
- Purchased top-ups are a separate lot and do not silently expire with monthly credits.
- Enterprise contracts can pool credits at organization level and allocate caps to workspaces or agents.

### Build pricing

- Each published template has a fixed activation price.
- A custom agent price is `base blueprint credits + selected ingredient credits`.
- Ingredients show their one-time and recurring credit impact before selection.
- Applying a recipe draft is free; credits reserve only when the user confirms creation.

### Runtime pricing

- A run reserves the maximum declared platform credits before dispatch.
- Completion reconciles actual platform credits and releases unused reservation.
- Exhaustion blocks a new run before provider or connector work begins.
- A run is never killed between an external side effect and its reconciliation solely because a balance crosses zero.

## BYOK inference contract

- Provider credentials are stored only in a supported secret vault; Convex stores opaque references.
- A workspace may define reusable provider connections and a default model route.
- Each agent may inherit the workspace default or bind a dedicated provider reference and route.
- The UI displays customer inference estimates and actuals independently from Agent Oven credits.
- Changing an agent binding requires admin authorization, validation, and an audit event.

## Hosted dependency

Agent blueprints are exportable, but hosted operation depends on Agent Oven for schedules/webhooks, connector sync, governed retrieval, trust policy, approval gates, metering, and receipts. Dispatch requires a short-lived signed runtime lease bound to organization, workspace, agent, blueprint version, budget, and allowed action digest.

## Fail-closed rules

- No negative balances.
- Idempotency key required for every reservation and reconciliation.
- No raw key, OAuth refresh token, or provider payload in credit records or receipts.
- No tenant can reserve, spend, release, or inspect another tenant's credits.
- Plan downgrade cannot silently remove evidence or active legal retention.
