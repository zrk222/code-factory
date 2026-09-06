# Spec: Post-publication runtime hardening

This is the next bounded upgrade after the 0.46.2 wheel is published. It is not part of that wheel's release claim.

## MUST - Requirements

### Requirements (EARS)

- When `REQ_PROOF_REUSE_RACE` verifies reusable evidence, it shall bind every stat, read and digest decision to one stable regular-file identity containing device, inode, size and modification time in nanoseconds, decode persisted manifests and receipts as UTF-8 canonical JSON, compute SHA-256 digests in bounded 1,048,576-byte chunks, compare pre-open, descriptor-open, post-read and post-close identities within 1 verification pass, return `PROOF_REUSE_BLOCKED` for missing identity, replacement, truncation, digest or symlink changes, keep legacy rows readable but not reusable, preserve unknown routed token counts as `null`, use the complete proof key plus a bounded 9-digit nanosecond nonce in savings identifiers, and rebind copied identities before its mutation challenge verifies that appended input bytes fail.
- When `REQ_PROCESS_ESCAPE` runs the Assembly command runner with a bounded command, it shall use a 300-second default deadline when no timeout is supplied and return `cleanup_confirmed=false` unless every descendant PID in the created POSIX group or Windows Job Object is terminated and observed exited within 10 seconds; a clean result shall require exit code 0 and Windows Job Object `ActiveProcesses` equal to 0, while any non-zero or unreadable value shall remain blocked.
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
