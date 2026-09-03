# Spec: appforge-release-rehearsal-v1

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

AppForge shall turn one hash-valid local submission dossier and one candidate-bound Fastlane, App Store Connect CLI, Cider, Swiftlane, or Zealot profile into a non-executing release rehearsal. It gives a human an exact, ordered handoff matrix so a build upload is never confused with processing, tester delivery, external beta review, App Review submission, or Apple approval.

### User roles

- **Release owner** supplies the exact candidate, an already-passing local assurance dossier, and a credential-free automation profile.
- **Human release operator** separately chooses whether to run a reviewed Fastlane lane, App Store Connect CLI command, Cider manifest, Swiftlane script, or Zealot distribution action in their authenticated environment.

### Requirements (EARS)

- When `REHEARSAL_ASSURANCE_BINDING` receives a workspace-local candidate and a hash-valid ready submission-assurance receipt with the same candidate, the system shall return `APPFORGE_REHEARSAL_ASSURANCE_BOUND` with two source digests. [R1]
- When `REHEARSAL_PROFILE_VALIDATE` receives `fastlane` with an alphanumeric lane name, `asc_cli` with a decimal app identifier, `cider` with a workspace-local UTF-8 YAML manifest path and SHA-256, `swiftlane` with a workspace-local UTF-8 Swift source hash and visible Workflow, Build, Test, Archive, and ExportArchive stages, or `zealot` with a candidate-bound artifact/platform/channel/audience manifest, the system shall return `APPFORGE_REHEARSAL_PROFILE_READY`; another provider shall return `APPFORGE_REHEARSAL_PROVIDER_REJECTED`. [R2]
- If `REHEARSAL_INPUT_GUARD` finds a credential-like key, an input above 1,048,576 bytes, a path escape, malformed digest, candidate mismatch, non-ready assurance receipt, or tampered assurance receipt, the system shall return a stable `APPFORGE_REHEARSAL_*` blocker and write 0 receipts. [R3]
- When `REHEARSAL_SEAL` receives all bindings, the system shall return `APPFORGE_RELEASE_REHEARSAL_READY` with an immutable SHA-256 sealed receipt, exact candidate, source digests, provider, channel, fixed state matrix, and human handoff guidance. [R4]
- If `REHEARSAL_STATE_MATRIX_CHECK` finds fewer or more than 9 stages, an external stage marked `ready`, or local readiness not marked `ready`, the system shall return `APPFORGE_REHEARSAL_STATE_INVALID` and write 0 receipts. [R5]
- If `REHEARSAL_INTERNAL_CHANNEL_CHECK` finds `testflight_internal` without external beta review and App Review submission marked `not_applicable`, the system shall return `APPFORGE_REHEARSAL_CHANNEL_INVALID` and write 0 receipts. [R6]
- If `REHEARSAL_EXTERNAL_CHANNEL_CHECK` finds `testflight_external` without App Review submission marked `not_applicable`, the system shall return `APPFORGE_REHEARSAL_CHANNEL_INVALID` and write 0 receipts. [R7]
- If `REHEARSAL_APP_STORE_CHANNEL_CHECK` finds `app_store` without tester states and external beta review marked `not_applicable`, the system shall return `APPFORGE_REHEARSAL_CHANNEL_INVALID` and write 0 receipts. [R8]
- When `REHEARSAL_NON_EXECUTION_CHECK` reads a rehearsal, the system shall return `APPFORGE_REHEARSAL_NON_EXECUTING` with `execution=false`, `credential_access=false`, `app_store_connect_write=false`, and `apple_approval_claim=false`; it does not invoke `subprocess`, HTTP, sockets, credential files, or approval APIs. [R9]
- When `REHEARSAL_STATUS_REQUESTED` reads a hash-valid rehearsal receipt, the system shall return `APPFORGE_RELEASE_REHEARSAL_READ_ONLY` through AppForge projection, MCP, WebMCP, and Graph Ops with no write-capable tool. [R10]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Produce a candidate-bound non-executing ASC rehearsal
  Given an exact candidate, a hash-valid ready local assurance dossier, and an ASC CLI profile with the same candidate
  When the release owner creates a rehearsal
  Then the output is SHA-256 sealed
  And local readiness is ready
  And upload, processing, tester delivery, submission, and approval remain not_attempted or not_applicable
  And no provider command or credential is executed

Scenario: Reject a profile that could misrepresent release state
  Given a profile with a candidate mismatch, secret-like key, or unknown provider
  When the release owner creates a rehearsal
  Then the system fails closed with a bounded finding
  And writes no release rehearsal receipt

Scenario: Every provider-state boundary is independently observable
  Given `REHEARSAL_STATE_MATRIX_CHECK`, `REHEARSAL_INTERNAL_CHANNEL_CHECK`, `REHEARSAL_EXTERNAL_CHANNEL_CHECK`, and `REHEARSAL_APP_STORE_CHANNEL_CHECK` run
  When `REHEARSAL_NON_EXECUTION_CHECK` reads a rehearsal
  Then `APPFORGE_REHEARSAL_STATE_INVALID` and `APPFORGE_REHEARSAL_CHANNEL_INVALID` remain distinct blockers
  And `APPFORGE_REHEARSAL_NON_EXECUTING` reports zero provider execution authority
```

## SHOULD - Technical/structural

- ADR references: local-first Fastlane boundary; ASC CLI dry-run/rehearsal and explicit provider-state separation; Cider declarative YAML-manifest hash binding; Swiftlane typed source-sequence hash binding; Zealot artifact/channel/audience manifest binding without provider execution.
- Data model: candidate JSON, `factory.appforge.release-automation-profile.v1`, `factory.appforge.beta-distribution-manifest.v1`, and `factory.appforge.release-rehearsal-receipt.v1`; declared facts are `assurance_valid`, `candidate_matches`, `profile_has_no_secret_keys`, `provider_valid`, and `provider_configuration_valid`; UTF-8 JSON inputs are at most 1,048,576 bytes, general text at most 160 characters, app identifiers at most 20 decimal characters, digest values at most 64 hexadecimal characters, and the release channel is one of `testflight_internal`, `testflight_external`, `app_store`, or `beta_distribution`.
- API contract: `factory revenue appforge-rehearse` and `factory.appforge_release_rehearsal_status`.

## SHOULD NOT - Implementation details

- Do not parse or execute arbitrary Fastfiles, Cider YAML, Swiftlane scripts, Zealot clients, shell commands, provider skills, CI files, or credentials.
- Do not call the Apple API or assert TestFlight/App Review state from a local artifact.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `REHEARSAL_ASSURANCE_BINDING` lacks a ready candidate match | `APPFORGE_REHEARSAL_ASSURANCE_BLOCKED` |
| 2 | `REHEARSAL_PROFILE_VALIDATE` finds an invalid provider configuration | `APPFORGE_REHEARSAL_PROVIDER_REJECTED` |
| 3 | `REHEARSAL_INPUT_GUARD` finds untrusted input | `APPFORGE_REHEARSAL_INPUT_REJECTED` |
| 4 | `REHEARSAL_SEAL` has all sealed bindings | `APPFORGE_RELEASE_REHEARSAL_READY` with external stages not attempted |
| 5 | `REHEARSAL_STATUS_REQUESTED` reads a receipt | `APPFORGE_RELEASE_REHEARSAL_READ_ONLY` |
