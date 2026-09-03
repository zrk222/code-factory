# Spec: enterprise-runner-supervision-v1

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Expose each decision-bound runner packet as reviewable local evidence. The
surface must distinguish a verified packet from an altered or malformed one
without executing its argv or becoming a runner authority.

### Requirements (EARS)

- When `RUNNER_PACKET_STATUS_REQUESTED` reads a packet whose schema, packet digest, decision digest, action class, scope, and argv digest are valid, the system shall return `RUNNER_ADMISSION_READ_ONLY` with one verified packet summary. [R1]
- When `GRAPH_OPS_ENTERPRISE_STATUS_REQUESTED` has a verified runner packet, the system shall return one `enterprise_runner_admission` node linked from the packet decision digest. [R2]
- When `MCP_ENTERPRISE_STATUS_REQUESTED` reaches the enterprise status tool, the system shall return the runner-packet projection with every authority flag false. [R3]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: A reviewer sees the exact runner input that was admitted
  Given one hash-valid admitted decision and matching runner packet
  When `GRAPH_OPS_ENTERPRISE_STATUS_REQUESTED` reads the local evidence
  Then the runner packet is shown as verified and linked to that decision
  And execution remains false

Scenario: A changed packet cannot be presented as governed work
  Given a malformed or altered runner packet
  When a read-only projection is requested
  Then the packet is counted invalid
  And no verified summary is returned for it
```

## SHOULD - Technical/structural

- Read no more than 500 packets below `.factory/enterprise-enforcement/runner-admissions/`.
- Preserve packet, decision, argv, action, and scope digests in every verified summary.

## SHOULD NOT - Implementation details

- Do not execute argv, call a provider, authenticate a workload, issue a
  credential, mutate a decision, prove a runner topology, or grant authority.

## Decision logic

| # | if | then |
|---|---|---|
| 1 | `RUNNER_PACKET_STATUS_REQUESTED` has valid packet binding | `RUNNER_ADMISSION_READ_ONLY` verified summary |
| 2 | `GRAPH_OPS_ENTERPRISE_STATUS_REQUESTED` has verified packet | `enterprise_runner_admission` linked node |
| 3 | `MCP_ENTERPRISE_STATUS_REQUESTED` reads enterprise status | runner projection and zero authority |
