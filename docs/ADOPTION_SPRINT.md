# 21-day adoption sprint

The first 21 days after the adoption release optimize one outcome: a new user
can see Code Factory catch a hollow test, understand the receipt, and decide
whether to use it on a real repository.

## Change boundary

- No new subsystem or architecture surface during the sprint.
- Allowed work: critical security or reliability fixes, first-run activation,
  documentation clarity, packaging, compatibility, and provider trust repairs.
- Every exception needs a named maintainer, reason, expiry, and linked evidence.
- Provider downloads are distribution signals, not people, users, or outcomes.

## Measured funnel

`factory adoption status --root .` aggregates only explicit local milestones:
`first_proof_started`, `hollow_test_caught`, `proof_card_created`,
`project_proof_started`, and `proof_verified`. Missing provider visits or
installs remain `null`; no identity or source is transmitted.

Success means fewer avoidable first-run failures and more voluntarily verified
proofs. It does not mean fabricated testimonials, automatic telemetry, or an
unsupported productivity claim.
