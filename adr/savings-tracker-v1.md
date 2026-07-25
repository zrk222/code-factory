# ADR: Paired savings tracking

## Decision

Add a local savings module that records one exact baseline observation beside
one exact Factory observation. It computes signed deltas per available metric.
Productivity gain remains unavailable unless a human explicitly asserts
equivalent outcomes and supplies an evidence file whose SHA-256 is stored.

## Rationale

The reviewed Codex history contains session-wide counters and Assembly wall
times but no matched counterfactuals. Those observations cannot support causal
savings claims. Pair receipts create the missing prospective evidence without
rewriting historical unknowns.

## Authority

The tracker may validate numeric input, hash a local evidence file, atomically
write local receipts, and export aggregate-safe reports. It may not execute the
baseline or Factory work, infer equivalence, upload telemetry, deploy, publish,
merge, sign, discover credentials, grant connectors, or send messages.

## Consequences

- Negative deltas remain visible.
- Missing paired fields remain null.
- Pair identifiers and evidence digests stay private.
- Public reports contain aggregates only.
- Outcome equivalence remains human-controlled; arithmetic is deterministic.
