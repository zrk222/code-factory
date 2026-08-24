# ADR: Supervised canary release safety

## Decision

Use Convex transactions to enforce one active canary per AgentSpec, mandatory deterministic and model re-evaluation, bounded traffic, evidence thresholds, and operator-only promotion or rollback.

## Boundary

This is a local security-alpha control surface. It neither invokes providers nor deploys production workloads, and it does not satisfy the commercial gate for hosted multi-tenancy.
