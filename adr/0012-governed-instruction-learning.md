# ADR 0012: Promote validated instructions, not accumulated reasoning

## Status

Accepted.

## Decision

Code Factory will create each worker context from task facts and the latest
owner-promoted task-specific AKU. Worker outcomes and proposed instructions are
untrusted candidates. A distinct validator must prove every current milestone
criterion with hash-bound local evidence, after which the recorded human owner
may activate the candidate. Worker, validator, and owner identities must be
distinct. Ordered milestone receipts block premature advancement.

The Architecture Opinion Dock remains a separate owner-controlled system of
record. Instruction promotion cannot modify it. Harbor and Terminal-Bench may
produce validation evidence, but neither benchmark scores nor external harness
execution grant promotion authority.

## Consequences

- New workers benefit from validated procedure without inheriting scratchpads.
- Reward hacking against one broad finish signal is reduced to criterion-level evidence.
- Failed candidates remain inspectable but inactive.
- External eval systems remain replaceable evidence sources rather than governors.
- Automatic instruction self-modification and autonomous promotion remain denied.
