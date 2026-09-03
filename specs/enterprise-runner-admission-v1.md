# Spec: enterprise-runner-admission-v1

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Bind one already-admitted local enterprise decision to a single runner input
without running that command. A production runner can consume the packet only
after it proves packet verification is its sole path to a consequential tool.

### Requirements (EARS)

- When `RUNNER_ADMISSION_REQUESTED` supplies a hash-valid admitted enterprise decision, one exact run identifier, matching action category, matching scope, and argv without shell operators, the system shall return `RUNNER_ADMISSION_PACKET_SEALED`. [R1]
- If `RUNNER_ADMISSION_SCOPE_CHECK` differs from the scope recorded in the admitted decision, the system shall return `E_RUNNER_SCOPE_MISMATCH` and write 0 packets. [R2]
- If `RUNNER_ADMISSION_COMMAND_CHECK` contains a shell operator, the system shall return `E_RUNNER_COMMAND_INVALID` and write 0 packets. [R3]
- If `RUNNER_ADMISSION_WRITE_CHECK` targets an existing packet, the system shall return `E_RUNNER_ADMISSION_IMMUTABLE` and write 0 packets. [R4]
- When `RUNNER_ADMISSION_PACKET_STATUS_REQUESTED` reads a packet, the system shall preserve `execution=false`; packet creation shall not run the argv, authenticate a workload, or establish real PEP topology. [R5]

### Acceptance criteria

```gherkin
Scenario: A runner receives only the exact admitted command
  Given one hash-valid admitted decision
  When a matching test argv and scope are sealed into a packet
  Then RUNNER_ADMISSION_PACKET_SEALED is returned
  And execution remains false

Scenario: A changed runner request is refused
  Given one admitted decision for tests
  When a runner packet names source paths or a shell operator
  Then an exact refusal is returned before a packet is written
```

## SHOULD - Technical/structural

- Store packets only under `.factory/enterprise-enforcement/runner-admissions/`.
- Bind argv with canonical JSON SHA-256 and reject overwrite/replay.

## SHOULD NOT - Implementation details

- Do not execute argv, call a provider, authenticate a cloud workload, or claim
  sidecar, eBPF, isolation, or production PEP enforcement.

## Decision logic

| # | if | then |
|---|---|---|
| 1 | `RUNNER_ADMISSION_REQUESTED` matches admitted decision | `RUNNER_ADMISSION_PACKET_SEALED` |
| 2 | `RUNNER_ADMISSION_SCOPE_CHECK` differs | `E_RUNNER_ADMISSION_MISMATCH` |
| 3 | `RUNNER_ADMISSION_COMMAND_CHECK` has shell operator | `E_RUNNER_COMMAND_INVALID` |
| 4 | `RUNNER_ADMISSION_WRITE_CHECK` overwrites or escapes directory | `E_RUNNER_ADMISSION_IMMUTABLE` |
| 5 | `RUNNER_ADMISSION_PACKET_STATUS_REQUESTED` reads packet | preserve `execution=false` |
