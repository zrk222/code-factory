# ADR: State-aware assembly continuation

## Decision

Add a new continuation layer above the legacy `assemble()` function. The layer
owns feature discovery, concise terminal semantics, automatic run receipts, and
privacy-safe aggregation. Both CLI and Studio call the same function.

## Rationale

Historical Codex usage showed that agents repeatedly reopened help and composed
long brick-specific command chains. Legacy assembly output is retained for
compatibility, while continuation supplies the missing state-aware front door.

## Authority

Continuation may execute local deterministic factory stages and write contained
evidence. It may not deploy, publish, merge, sign, inject credentials, grant
connectors, or send external messages.

## Consequences

- Waiting for a human is a distinct terminal state and exit code.
- Usage evidence is automatic, but token and cost fields remain unknown unless
  an adapter supplies exact values.
- Public exports are aggregate-only and omit repository and feature identity.
