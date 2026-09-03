# Spec: appforge-fastlane-capture-v1

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

AppForge shall seal a Windows-operable, capture-only Fastlane Snapshot contract
that binds the exact candidate, a ready Device-Family Matrix, and a ready
Storefront Story before a separately authorized macOS/Xcode run. It shall never
run Fastlane, Xcode, a simulator, a device, signing, upload, delivery, review,
or Apple action.

### Declared facts

- `candidate_matches`: all bound candidate objects are equal.
- `matrix_ready`: the supplied Surface Matrix is hash-valid and ready.
- `story_ready`: the supplied Storefront Story is hash-valid and ready.
- `scene_coverage_complete`: every reviewed scene has exactly one safe snapshot name.
- `snapfile_deterministic`: required devices, locale, scheme, cleanup, `override_status_bar(true)`, and stop-on-error settings exist.
- `capture_lane_only`: the named Fastfile lane captures only and lacks sign/upload/delivery/review actions.
- `ui_test_coverage_complete`: setup, launch, failure policy, and every sealed snapshot call exist statically.
- `windows_preflight_supported`: `windows_operation.local_preflight_supported` equals `true` and `windows_operation.external_execution_requires_macos_xcode` equals `true`.
- `capture_lane_refusal_code`: `APPFORGE_FASTLANE_CAPTURE_LANE_INVALID` identifies an unsafe or non-capture-only Fastfile lane.

### Requirements (EARS)

- When `FASTLANE_CAPTURE_BINDING` receives matching sealed matrix and story receipts, a fixed-shape local contract, and local Fastlane sources, the system shall write a SHA-256 sealed `APPFORGE_FASTLANE_CAPTURE_READY` receipt. [R1]
- If `FASTLANE_CAPTURE_GUARD` detects a candidate mismatch, missing or duplicate scene mapping, missing required Snapfile setting, or missing snapshot call, the system shall return one refusal code and write 0 ready receipts. If it detects `upload_to_app_store`, `deliver`, `pilot`, `upload_to_testflight`, `match`, or `sync_code_signing` inside the declared lane, it shall return `APPFORGE_FASTLANE_CAPTURE_LANE_INVALID` and write 0 ready receipts. [R2]
- When `FASTLANE_WINDOWS_HANDOFF` writes a ready receipt, the system shall emit `windows_operation.local_preflight_supported=true`, `windows_operation.external_execution_requires_macos_xcode=true`, and one non-empty reason string naming macOS/Xcode as the separate execution environment. [R3]
- When `FASTLANE_CAPTURE_STATUS_REQUESTED` reads receipts, AppForge, Graph Ops, and MCP shall return bounded read-only status with execution, device, credential, provider-write, submission, and Apple-approval authority false. [R4]

### Acceptance criteria

```gherkin
Scenario: Prepare a repeatable capture plan on Windows
  Given ready candidate-bound surface and storefront receipts
  When an owner validates a capture-only Fastlane contract
  Then every reviewed scene has exactly one static snapshot call
  And no Xcode, simulator, Fastlane, provider, or Apple action occurs

Scenario: Refuse a disguised release lane
  Given a declared Fastlane capture lane includes upload_to_app_store
  When the contract is validated
  Then it refuses with APPFORGE_FASTLANE_CAPTURE_LANE_INVALID
  And writes no ready receipt
```

## SHOULD - Technical/structural

- API: `factory revenue appforge-fastlane-capture`.
- Data schema: `factory.appforge.fastlane-capture-*.v1`.
- Inputs remain workspace-local and are bounded to 1 MiB.

## SHOULD NOT - Non-goals

- Do not execute Fastlane or Xcode from the Windows control plane.
- Do not assert static source checks prove a UI test passed or that a screenshot depicts a feature.
- Do not upload screenshots or claim App Store readiness or approval.
