# ADR: Transactional incident containment

## Decision

Use one Convex mutation to suspend the agent, close pending run authority, roll back active canaries, and append incident evidence. Recovery is supervised and requires five unique deterministic checks before service resumes.

## Boundary

This is a local recovery rehearsal. It does not page external responders, rotate real credentials, or claim production incident-management readiness.
