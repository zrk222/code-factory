# Spec: Post-publication runtime hardening

This is the next bounded upgrade after the 0.46.2 wheel is published. It is not part of that wheel's release claim.

## MUST - Requirements

### Requirements (EARS)

- When `REQ_PROOF_REUSE_RACE` verifies reusable evidence, it shall bind every stat, read and digest decision to one stable file identity and return `PROOF_REUSE_BLOCKED` for replacement, truncation or symlink changes observed during verification.
- When `REQ_PROCESS_ESCAPE` runs a bounded command, it shall return `cleanup_confirmed=false` unless every descendant PID in the created POSIX group or Windows Job Object is terminated and observed exited within 10 seconds.
- When `REQ_POSIX_PARITY` validates command-runner behavior on Linux and macOS, it shall return `timed_out` for a 1 seconds fixture, `output_limit_exceeded` for a 4194305 bytes fixture, `cancelled` for 1 cancellation fixture and `cleanup_confirmed=false` for 1 surviving-child fixture.
- When `REQ_STUDIO_STRUCTURE` inspects `create_product_mission_from_studio`, `do_GET` and `do_POST`, it shall return pass only when every named function contains 10 or fewer decision branches without changing HTTP behavior.
- While `REQ_RUNTIME_AUTHORITY` evaluates this upgrade, it shall return publication, deployment, signing, messaging, credential and connector authority as false.

### Acceptance criteria

```gherkin
Scenario: Replaced proof evidence fails closed
  Given REQ_PROOF_REUSE_RACE observes a proof file replaced between identity checks
  When reuse eligibility is decided
  Then REQ_PROOF_REUSE_RACE returns PROOF_REUSE_BLOCKED and no reusable proof

Scenario: Escaped child prevents a clean result
  Given REQ_PROCESS_ESCAPE starts a child that survives its parent
  When cancellation or timeout cleanup completes
  Then REQ_PROCESS_ESCAPE returns cleanup unconfirmed within 10 seconds

Scenario: Native runners return the same closed decisions
  Given REQ_POSIX_PARITY runs the four bounded Linux and macOS fixtures
  When timeout overflow cancellation and surviving-child decisions are collected
  Then REQ_POSIX_PARITY returns timed_out output_limit_exceeded cancelled and cleanup_confirmed false

Scenario: Studio routing stays behaviorally identical
  Given REQ_STUDIO_STRUCTURE captures the current request and response contract as golden tests
  When its three coordinators are decomposed
  Then REQ_STUDIO_STRUCTURE passes every golden and returns 10 or fewer decision branches per coordinator

Scenario: Planned runtime hardening has no external authority
  Given REQ_RUNTIME_AUTHORITY evaluates one planned hardening receipt
  When the receipt is returned
  Then REQ_RUNTIME_AUTHORITY returns publication deployment signing messaging credential and connector authority as false
```

## Non-goals

The system shall not publish this planned upgrade with the 0.46.2 wheel or claim kernel isolation before native evidence exists.
