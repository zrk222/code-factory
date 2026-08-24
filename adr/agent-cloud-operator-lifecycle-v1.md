# ADR: Append-only operator lifecycle and secret references

## Status

Accepted — 2026-07-20

## Decision

Keep AgentSpec history append-only, model rollback as a new head version, and store only typed external secret references for BYOK. Pause closes pending authority; revoke is irreversible. Convex remains the exclusive application backend.

## Rationale

An operator must be able to explain and reverse configuration changes without erasing the audit trail. Hosted secret custody is outside the current pilot boundary, so provider credentials remain in an operator-controlled environment or vault and product records contain references only.

## Consequences

- Export/import can round-trip the seven semantic AgentSpec fields without database identifiers or timestamps.
- A rollback records who restored which version and never mutates historical snapshots.
- Emergency control is enforced in the same transaction that closes pending runs and approvals.
- A later production secret broker can resolve the existing references without migrating raw secret values out of Convex.
