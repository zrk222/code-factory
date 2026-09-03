# Spec: appforge-device-reality-v1

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Give an AppForge user a local, supervised Device Reality Gate that binds physical-device capture evidence to one hash-sealed intent envelope. The envelope freezes the exact release candidate, user-design input digest, human/trusted-source Oracle obligations, required journeys, forbidden outcomes, and allowed capture transport before a worker collects evidence. It prevents a desktop, simulator, or agent narrative from being treated as real-device evidence.

### User roles

- Release owner: seals intent through a named human AppForge Oracle Authority.
- Supervised capture operator: collects local artifacts after user authorization.
- Connected agent: reads only bounded status through MCP/WebMCP; never controls a device.

### Requirements (EARS)

- When `DEVICE_REALITY_ORACLE_BINDING` receives a current candidate-bound AppForge Oracle Authority receipt and a current sealed Oracle Contract, the system shall return `DEVICE_REALITY_ORACLE_BOUND` with `oracle_contract.contract_sha256`. [R1]
- When `DEVICE_REALITY_DESIGN_BINDING` receives reviewed design input, the system shall return `DEVICE_REALITY_DESIGN_BOUND` with `user_design_input.sha256`. [R2]
- When `DEVICE_REALITY_JOURNEY_SEALING` receives a named human reviewer, required journey list, forbidden outcome list, and transport allowlist, the system shall return `DEVICE_REALITY_JOURNEYS_SEALED` with `required_journeys`, `allowed_transports`, and `envelope_sha256`. [R3]
- If `DEVICE_REALITY_ENVELOPE_BYTE_CHECK` finds a changed envelope byte, the system shall return `APPFORGE_DEVICE_REALITY_ENVELOPE_TAMPERED` and write 0 Device Reality receipts. [R4]
- If `DEVICE_REALITY_ENVELOPE_DIGEST_CHECK` finds an envelope SHA-256 different from recorded `envelope_sha256`, the system shall return `APPFORGE_DEVICE_REALITY_ENVELOPE_DIGEST_MISMATCH` and write 0 Device Reality receipts. [R5]
- When `DEVICE_REALITY_EVIDENCE_READY_CHECK` receives the exact sealed candidate, envelope digest, design-input digest, named envelope approver, human-presence assertion, user-authorized transport, and exactly one hash-valid artifact for every sealed journey, the system shall return `APPFORGE_DEVICE_REALITY_READY` with `execution=false` and `capture_execution=false`. [R6]
- If `DEVICE_REALITY_EVIDENCE_BLOCK_CHECK` finds a missing journey, duplicate journey, changed candidate, changed design digest, changed transport, changed forbidden outcome, workspace escape, or artifact SHA-256 mismatch, the system shall return `APPFORGE_DEVICE_REALITY_BLOCKED` with a stable finding code. [R7]
- If `DEVICE_REALITY_PHONE_HARNESS_CHECK` receives `phone_harness`, the system shall return `DEVICE_REALITY_TRANSPORT_DECLARED` with `device_control=false`, `capture_execution=false`, `credential=false`, `app_store_connect_write=false`, and `apple_approval_claim=false`. [R8]
- When `DEVICE_REALITY_STATUS_REQUESTED` reads a hash-valid Device Reality receipt, the system shall return `APPFORGE_DEVICE_REALITY_READ_ONLY` through AppForge projection, local MCP, and Graph Ops WebMCP with no device, provider, or release authority. [R9]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Supervised physical-device evidence matches sealed intent
  Given a current sealed Oracle Contract, candidate-bound AppForge authority, and reviewed user-design input
  When a release owner seals two journeys and a human supervises two hash-valid authorized captures
  Then DEVICE_REALITY_EVIDENCE_READY_CHECK returns APPFORGE_DEVICE_REALITY_READY
  And the receipt names the exact candidate and envelope digest
  And no device, Phone Harness, Apple, credential, submission, or approval action runs

Scenario: Every Device Reality requirement has a named proof marker
  Given `DEVICE_REALITY_ORACLE_BINDING`, `DEVICE_REALITY_DESIGN_BINDING`, and `DEVICE_REALITY_JOURNEY_SEALING` are recorded
  When `DEVICE_REALITY_ENVELOPE_BYTE_CHECK`, `DEVICE_REALITY_ENVELOPE_DIGEST_CHECK`, and `DEVICE_REALITY_EVIDENCE_READY_CHECK` run
  Then `DEVICE_REALITY_EVIDENCE_BLOCK_CHECK`, `DEVICE_REALITY_PHONE_HARNESS_CHECK`, and `DEVICE_REALITY_STATUS_REQUESTED` remain independently observable

Scenario: A worker attempts to weaken the approved device expectation
  Given a sealed Device Reality intent envelope
  When the worker changes a forbidden outcome, removes a journey, or removes human supervision
  Then DEVICE_REALITY_ENVELOPE_BYTE_CHECK returns APPFORGE_DEVICE_REALITY_ENVELOPE_TAMPERED
  And DEVICE_REALITY_EVIDENCE_BLOCK_CHECK returns APPFORGE_DEVICE_REALITY_BLOCKED
  And the receipt contains the exact blocker code
```

## SHOULD - Technical/structural

- ADR references: existing Oracle Firewall authority model and AppForge Oracle bridge.
- Data model: `factory.appforge.device-reality-intent-envelope.v1`, `factory.appforge.device-reality-evidence.v1`, and `factory.appforge.device-reality-receipt.v1`; UTF-8 JSON inputs are at most 1,048,576 bytes, a capture artifact is at most 25 MiB, general text is at most 500 characters, SHA-256 values and transport names are at most 64 characters, candidate values are at most 200 characters, journey identifiers are at most 96 characters, reviewer names are at most 160 characters, and capture paths are at most 512 characters.
- API contract: `factory revenue device-reality-intent`, `factory revenue device-reality-gate`, `factory.appforge_device_reality_status`, and Graph Ops WebMCP status.

## SHOULD NOT - Implementation details

- Do not vendor, invoke, or require a specific device tool.
- Do not elevate supplied screenshots or metadata into semantic proof, Apple policy certification, TestFlight state, submission, or approval.
- Do not make the Device Reality lane globally mandatory for existing submission dossiers in v1; later contracts may explicitly require it.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `DEVICE_REALITY_ORACLE_BINDING` has a current Oracle Authority and sealed contract | `DEVICE_REALITY_ORACLE_BOUND` |
| 2 | `DEVICE_REALITY_ENVELOPE_BYTE_CHECK` finds changed envelope bytes | `APPFORGE_DEVICE_REALITY_ENVELOPE_TAMPERED` |
| 3 | `DEVICE_REALITY_EVIDENCE_BLOCK_CHECK` finds changed candidate/design/supervision/transport/journey/outcome/artifact facts | `APPFORGE_DEVICE_REALITY_BLOCKED` |
| 4 | `DEVICE_REALITY_EVIDENCE_READY_CHECK` has exactly one supervised, authorized, hash-valid passing observation for every sealed journey | `APPFORGE_DEVICE_REALITY_READY` |
| 5 | `DEVICE_REALITY_STATUS_REQUESTED` reads a receipt | `APPFORGE_DEVICE_REALITY_READ_ONLY` with zero execution authority |
