# ADR — Bind permission at execution time

## Decision

Agent Cloud uses short-lived, single-use Convex capability records bound to one independently approved run action. Authorization compares subject, audience, scope, resource, environment, action digest, expiry, revocation state, and cost. A successful decision atomically consumes the grant and reserves spend. Failed decisions throw exact codes before writes.

## Why

Plan-time approval alone can become stale or be applied to a different connector, resource, or payload. Execution-time binding narrows that gap, while a one-use state prevents replay and atomic reservation prevents policy approval from racing the cost ledger.

## Consequences

This is a supervised local enforcement gateway, not a cryptographically signed or remotely portable token system. A future hosted adapter may exchange the local record for a connector-specific credential only after this mutation succeeds. Denials are returned to the caller but are intentionally not persisted in v1 so fail-closed rejection remains side-effect free.
