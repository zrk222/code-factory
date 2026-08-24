# ADR: Agent Cloud memory governance v1

## Decision

Implement the first Phase 2 security-alpha slice as a local Convex memory-governance lifecycle. Corrections append a successor and supersede the predecessor. Erasure removes sensitive fields while preserving a non-sensitive tombstone and append-only receipt. Export is canonical, portable, and excludes database identifiers and receipt fingerprints. Retention uses the server clock and the same erasure primitive.

## Boundary

Memory remains untrusted context and cannot authorize actions. This milestone does not begin or claim hosted multi-tenancy, production identity, billing, or WizeMe source reuse. Those remain behind the PRD’s commercial, provenance, and security gates.

## Consequences

- Historical corrections remain reviewable until explicitly erased or expired.
- Deleted content is unavailable through active retrieval and export.
- Audit and receipt evidence remain append-only but contain no deleted content.
- The UI can explain provenance and lifecycle state without becoming an authority surface.
