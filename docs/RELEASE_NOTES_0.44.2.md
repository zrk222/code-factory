# Code Factory 0.44.2 — Intent lineage navigation

## What changed

- Graph Ops now shows a compact **Intent trace → Forge ship line** path when a
  Factoryline adapter is hash-bound to a readable Forge receipt.
- **Inspect source** focuses the existing local `intent_source` node and exact
  ship line; it never refreshes evidence or grants authority.
- Missing, malformed, invalid, and mismatched bindings display
  **No traversable Forge lineage** and withhold navigation.
- Versioned release metadata, MCP registry descriptors, install examples, and
  public release links now point to `0.44.2`.

## Evidence boundary

This release adds reviewer navigation, not a production-readiness claim. Graph
Ops remains local and read-only; execution, repair, approval, publication,
deployment, signing, messaging, credential, and connector authority remain
false.

## Verification

- Full Python suite and package build are release gates in `publish.yml`.
- Focused Graph Ops visual and adapter tests cover bound and fail-closed states.
- ForgeLine and SpecLine receipts are recorded for the intent-lineage
  navigation slice.
