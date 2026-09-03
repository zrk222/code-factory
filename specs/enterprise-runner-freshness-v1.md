# Spec: enterprise-runner-freshness-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Make every local runner-admission packet fail closed after the signed workload
identity that admitted its decision expires. This gives a supervised enterprise
pilot a bounded, inspectable freshness signal without executing a command or
claiming live authorization.

### User roles
- Enterprise operator: inspects Graph Ops or MCP before a separate runner uses
  a local packet.
- Separate runner: independently verifies one packet before any consequential
  action; this repository does not implement that runner.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- When `RUNNER_ADMISSION_FRESHNESS_SEAL` receives a current signed identity whose maximum lifetime is 24 hours, the system shall return `RUNNER_ADMISSION_PACKET_SEALED` with `admission_expires_at` identical to `workload_identity.expires_at`. [R1]
- If `RUNNER_ADMISSION_EXPIRY_CHECK` finds `workload_identity.expires_at` at or before `verification_clock` within the 24 hours identity lifetime, the system shall return `E_RUNNER_ADMISSION_EXPIRED` and write 0 packets. [R2]
- If `RUNNER_ADMISSION_EXPIRY_MISSING_CHECK` finds a missing `admission_expires_at` within the 24 hours identity lifetime, the system shall return `E_RUNNER_FRESHNESS_MISSING` and write 0 packets. [R3]
- If `RUNNER_ADMISSION_EXPIRY_MALFORMED_CHECK` finds a malformed `admission_expires_at` within the 24 hours identity lifetime, the system shall return `E_RUNNER_FRESHNESS_INVALID` and write 0 packets. [R4]
- If `RUNNER_ADMISSION_EXPIRY_MISMATCH_CHECK` finds `admission_expires_at` different from `workload_identity.expires_at` within the 24 hours identity lifetime, the system shall return `E_RUNNER_FRESHNESS_MISMATCH` and write 0 packets. [R5]
- When `RUNNER_ADMISSION_PACKET_STATUS_REQUESTED` reads a hash-valid fresh packet, the system shall return `RUNNER_ADMISSION_READ_ONLY` with `execution=false`; packet verification shall not call subprocess, HTTP client, socket, credential, or approval APIs. [R6]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: current signed identity produces a fresh packet
  Given an admitted decision records a signed workload identity expiry 30 minutes in the future
  When a packet binds that decision, scope, action, and argv digest
  Then packet verification returns the exact recorded expiry and the projection reports 1 fresh packet

Scenario: packet expires after its signed identity window
  Given a sealed packet whose identity-derived expiry is earlier than the verification clock
  When local packet verification is requested
  Then verification returns E_RUNNER_ADMISSION_EXPIRED and the projection reports 1 expired packet and 0 verified packets

Scenario: missing expiry is refused before a packet is trusted
  Given a packet whose admission_expires_at is absent
  When RUNNER_ADMISSION_EXPIRY_MISSING_CHECK verifies the packet
  Then E_RUNNER_FRESHNESS_MISSING is returned and 0 packets are written

Scenario: malformed expiry is refused before a packet is trusted
  Given a packet whose admission_expires_at is malformed
  When RUNNER_ADMISSION_EXPIRY_MALFORMED_CHECK verifies the packet
  Then E_RUNNER_FRESHNESS_INVALID is returned and 0 packets are written

Scenario: expiry must remain bound to the admitted identity
  Given a packet whose admission_expires_at differs from workload_identity.expires_at
  When RUNNER_ADMISSION_EXPIRY_MISMATCH_CHECK verifies the packet
  Then E_RUNNER_FRESHNESS_MISMATCH is returned and 0 packets are written

Scenario: runner input remains non-executing
  Given a hash-valid fresh packet contains an argv
  When RUNNER_ADMISSION_PACKET_STATUS_REQUESTED reads the projection
  Then RUNNER_ADMISSION_READ_ONLY is returned with execution false and zero process, network, credential, or approval action
```

## SHOULD — Technical/structural
- ADR references: docs/ENTERPRISE_ENFORCEMENT.md
- Data model: admitted decision gains `workload_identity.issued_at` and
  `workload_identity.expires_at`; packet gains `admission_expires_at`; the
  verification clock is an explicit UTC timestamp supplied by the verifier or
  the local UTC clock. The projection exposes `fresh_count`, `expired_count`,
  and `invalid_count` integer fields.
- API contract: `verify_runner_admission_packet(root, path, now=None)` returns
  `admission_expires_at`; `runner_admission_projection` adds `fresh_count` and
  `expired_count` without adding authority.

## SHOULD NOT — Implementation details
<!-- Leave the "how" to the plan/tasks unless it is a systemic invariant -->

- This slice does not add a hosted PEP, a sidecar/eBPF policy point, live
  revocation polling, runner execution, or a production authorization claim.

## Decision logic (factory candidates)
<!-- Ordered business rules over extracted facts. specline handoff compiles
     these via HSF instead of letting agents improvise them. -->
| # | if | then |
|---|----|------|
| 1 | `RUNNER_ADMISSION_FRESHNESS_SEAL` has a current identity expiry | `RUNNER_ADMISSION_PACKET_SEALED` |
| 2 | `RUNNER_ADMISSION_EXPIRY_CHECK` finds expiry at or before the verification clock | `E_RUNNER_ADMISSION_EXPIRED` |
| 3 | `RUNNER_ADMISSION_EXPIRY_MISSING_CHECK` finds missing expiry | `E_RUNNER_FRESHNESS_MISSING` |
| 4 | `RUNNER_ADMISSION_EXPIRY_MALFORMED_CHECK` finds malformed expiry | `E_RUNNER_FRESHNESS_INVALID` |
| 5 | `RUNNER_ADMISSION_EXPIRY_MISMATCH_CHECK` finds different expiry | `E_RUNNER_FRESHNESS_MISMATCH` |
| 6 | `RUNNER_ADMISSION_PACKET_STATUS_REQUESTED` reads fresh packet | `RUNNER_ADMISSION_READ_ONLY` and `execution=false` |
