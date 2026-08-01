# ADR: Content-addressed proof reuse

## Decision

Add local proof receipts keyed by relevant source hashes, command digest,
toolchain, and environment. Route each requested gate to RUN, REUSE, SKIP, or
BLOCK. Reuse is restricted to exact green read-only validation.

## Rationale

July 2026 contained 66 IntelliJ workflow launches for 42 unique head SHAs. The
24 duplicate-SHA launches executed 216 jobs and consumed 1101.3 runner-minutes.
This is measured historical duplicate work, not a prospective savings claim.

Content-addressed validation makes identical evidence reusable while keeping a
closed authority boundary and generating prospective paired measurements.

## Authority

The router may validate manifests, hash workspace files, verify local receipts,
write compact plans, challenge one isolated input copy, and record an exact
paired savings observation. It may not execute a requested gate, publish,
deploy, sign, approve, discover credentials, grant connectors, or send an
external message.

## Consequences

- Missing or ambiguous relevance fails closed to RUN.
- Side-effecting gates are BLOCK, never REUSE.
- A changed input or output invalidates an old receipt.
- Automatic savings exist only for verified prospective reuse.
- Historical duplicate runner-minutes remain an opportunity baseline.

