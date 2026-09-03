# Spec: appforge-surface-integrity-v1

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

AppForge shall create a local, candidate-bound Surface Integrity packet that
connects confirmed design input, native Swift source, required physical-device
configurations, and truthful Storefront story coverage. The packet is a
deterministic planning and evidence boundary; it must not imply a device,
App Store Connect, TestFlight, App Review, or Apple-approval action.

### User roles

- **Product/design owner** confirms the user design input and the resulting
  design, accessibility, material, storyboard, and claim decisions.
- **Build owner** supplies the exact candidate and workspace-local Swift,
  Store-media, and evidence files.
- **Supervised device operator** separately captures the planned
  configurations through Device Reality.

### Declared facts

- `candidate_matches`: the exact candidate objects are equal.
- `design_input_confirmed`: the contract contains the confirmed design-input digest.
- `swift_sources_local`: every declared Swift source stays within the workspace.
- `native_review_confirmed`: a named native-surface review confirms all required decisions.
- `native_contract_valid`: the native-surface contract has the fixed valid shape.
- `static_source_findings_present`: static source analysis produced one or more blocker findings.
- `native_receipt_ready`: the supplied native-surface receipt is sealed and ready.
- `supervised_device_evidence_required`: every matrix scenario is awaiting physical-device evidence.
- `store_media_ready`: the supplied Store-media receipt is sealed and ready.
- `scene_coverage_complete`: every ready Store-media capture appears once in the story contract.
- `claim_evidence_valid`: every non-experience claim has workspace-local evidence references.
- `story_review_confirmed`: a named review confirms storyboard truth and claim check.
- `high_risk_claim_sourced`: no high-risk claim appears without the measured posture.
- `receipt_projection_requested`: a local status view is requested.

### Requirements (EARS)

- When `NATIVE_SURFACE_BINDING` receives a workspace-local candidate, confirmed design-input SHA-256, 1-100 local Swift files, a unique iPhone/iPad list, fixed adaptive/accessibility/material/storyboard fields, and a named RFC3339 review, the system shall return a SHA-256 sealed `APPFORGE_NATIVE_SURFACE_READY` receipt or a bounded `APPFORGE_NATIVE_SURFACE_BLOCKED` receipt. [R1]
- If `NATIVE_SURFACE_STATIC_GUARD` finds `UIScreen.main.bounds`, `UIApplication.shared.windows`, declared iPad without one accepted adaptive API, custom glass above its declared cap, or icon-label review debt, the system shall return `APPFORGE_NATIVE_SURFACE_BLOCKED` with bounded findings and shall never call a renderer, simulator, device, asset source, or Apple provider. [R2]
- When `SURFACE_MATRIX_EXPAND` receives a SHA-256 sealed ready Native Surface receipt with the same candidate, the system shall return a sealed `APPFORGE_SURFACE_MATRIX_WRITTEN` receipt containing iPhone/iPad, Split View, Dynamic Type, Reduce Motion, Reduce Transparency, Increase Contrast, and VoiceOver configurations marked `supervised physical-device capture`. [R3]
- If `SURFACE_MATRIX_GUARD` finds an unsealed, non-ready, candidate-mismatched, or unsupported-platform Native Surface receipt, the system shall reject input with `APPFORGE_SURFACE_MATRIX_NATIVE_SURFACE_INVALID` and write 0 matrix receipts. [R4]
- When `STOREFRONT_STORY_BINDING` receives a SHA-256 sealed ready Store-media receipt with the same candidate, one unique scene per capture, one supported story beat, and named RFC3339 review, the system shall return a SHA-256 sealed `APPFORGE_STOREFRONT_STORY_READY` receipt. [R5]
- If `STOREFRONT_STORY_GUARD` finds a capture mapped other than exactly once, a feature or measured claim without 1-8 local evidence references, an invalid review, or a high-risk factual claim without measured posture, the system shall return `APPFORGE_STOREFRONT_STORY_BLOCKED` and shall never generate or upload media. [R6]
- When `SURFACE_INTEGRITY_STATUS_REQUESTED` reads a hash-valid receipt, AppForge, Graph Ops, MCP, and WebMCP shall return bounded read-only projections with execution, device access, asset download, provider write, and approval claim authority set false. [R7]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Expand one sealed design/source decision into physical-device work
  Given a ready Native Surface receipt for an iPhone and iPad candidate
  When the build owner creates a Device-Family Matrix
  Then every listed configuration requires supervised physical-device evidence
  And no simulator, device, screenshot, or provider action occurs

Scenario: Keep screenshot marketing tied to real work
  Given ready exact-build Store media with one iPhone and one iPad capture
  When the owner maps each capture to one reviewed scene
  Then no capture is uncovered or duplicated
  And high-risk unsourced claims block instead of reaching a storefront handoff

Scenario: Preserve external decision boundaries
  Given every Surface Integrity receipt is hash-valid
  When an MCP or WebMCP client reads status
  Then it receives only local read-only metadata
  And it cannot generate media, access credentials, operate a device, upload, submit, or claim approval
```

## SHOULD - Technical/structural

- Data schemas: `factory.appforge.native-surface-*.v1`,
  `factory.appforge.surface-matrix-receipt.v1`, and
  `factory.appforge.storefront-story-*.v1`.
- API: `factory revenue appforge-native-surface`,
  `factory revenue appforge-surface-matrix`,
  `factory revenue appforge-storefront-story`, and three matching read-only
  MCP/WebMCP status tools.
- Inputs remain workspace-local, bounded to 1 MiB for JSON and verified with
  deterministic canonical SHA-256 receipts.

## SHOULD NOT - Implementation details

- Do not vendor Apple assets, Figma/Sketch kits, Swift templates, device
  bezels, or third-party source.
- Do not interpret file references as semantic claim proof.
- Do not make App Review or acceptance claims from local evidence.

## Decision logic

| # | if | then |
|---|----|------|
| 1 | `native_contract_valid` | `APPFORGE_NATIVE_SURFACE_READY` |
| 2 | `static_source_findings_present` | `APPFORGE_NATIVE_SURFACE_BLOCKED` |
| 3 | `native_receipt_ready` | `APPFORGE_SURFACE_MATRIX_WRITTEN` |
| 4 | `scene_coverage_complete` | `APPFORGE_STOREFRONT_STORY_READY` |
| 5 | `high_risk_claim_sourced` is false | `APPFORGE_STOREFRONT_STORY_BLOCKED` |
| 6 | `receipt_projection_requested` | read-only local projection |
