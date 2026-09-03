# AppForge Native Surface Truth Gate

AppForge Native Surface Truth is a **local static preflight** for the gap
between a good-looking storyboard and a build that behaves poorly on an iPad,
with accessibility settings, or with excessive custom visual treatment.

It binds one release candidate, confirmed user design input, local Swift source,
an adaptive-navigation contract, accessibility expectations, a restrained
custom-glass budget, and a device-specific App Store storyboard. It cannot run
Swift, render a screen, fetch Apple assets, access a device, contact Apple, or
claim App Review approval.

## Why it exists

Apple's own guidance says standard system controls adopt Liquid Glass
automatically, custom glass should be sparse, and the content layer should not
be filled with Liquid Glass. It also calls out adaptation to different windows
and accessibility settings. AppForge turns the parts that can be safely checked
locally into a source-bound review lane; physical-device evidence stays in
[Device Reality](APPFORGE_DEVICE_REALITY.md).

The gate does **not** vendor, copy, or redistribute Apple assets, Figma kits,
device bezels, templates, or third-party Swift source. The referenced projects
are learning patterns only.

## Inputs

1. Candidate: `factory.appforge.release-candidate.v1`.
2. Contract: `factory.appforge.native-surface-contract.v1`.
3. Named human review evidence: `factory.appforge.native-surface-evidence.v1`.

The contract has an exact field set. For an iPad-capable app it must name both
platforms, use `split_or_sidebar` for iPad navigation, bind each Swift source
file inside the workspace, require a scene for every declared platform, reject
hard-coded screen geometry, and cap custom glass at zero through three
controls.

```json
{
  "schema": "factory.appforge.native-surface-contract.v1",
  "candidate": {
    "bundle_identifier": "app.example.calm",
    "version": "1.0",
    "build_number": "42",
    "source_commit": "abc123"
  },
  "user_design_input_sha256": "<64 lowercase hex characters>",
  "platforms": ["iphone", "ipad"],
  "source_files": ["App/HomeView.swift"],
  "adaptive": {
    "iphone_navigation": "tabs_or_stack",
    "ipad_navigation": "split_or_sidebar",
    "independent_destination_paths": true,
    "hardcoded_screen_geometry_allowed": false
  },
  "accessibility": {
    "dynamic_type": true,
    "reduce_motion": true,
    "reduce_transparency": true,
    "icon_labels": true
  },
  "materials": {
    "system_components_preferred": true,
    "content_layer_glass_allowed": false,
    "max_custom_glass_controls": 2
  },
  "storyboard": [
    {"id": "iphone-home", "platform": "iphone", "journey": "first value", "user_value": "understand today"},
    {"id": "ipad-workspace", "platform": "ipad", "journey": "core workspace", "user_value": "work with context"}
  ]
}
```

The review evidence must be bound to the exact contract file hash and contain a
named human confirmation for adaptive navigation, accessibility fallbacks,
material hierarchy, and storyboard truth.

## Run

```powershell
factory revenue appforge-native-surface `
  --root . `
  --candidate .factory/appforge/candidate.json `
  --contract appforge/native-surface-contract.json `
  --evidence appforge/native-surface-evidence.json `
  --out .factory/appforge/native-surface.json `
  --json
```

The receipt blocks on known unsafe patterns:

- direct `UIScreen.main.bounds` or `UIApplication.shared.windows` use;
- no recognized adaptive SwiftUI API in an iPad-capable source set;
- more custom `glassEffect` calls than the approved budget;
- an icon-to-explicit-label mismatch that needs VoiceOver review;
- candidate, contract, design-input, source-path, or human-review drift.

Absence of a source string is never treated as proof of a failure where Apple
system components adapt automatically. Instead, the receipt reports observed
signals and keeps actual layout, VoiceOver, contrast, material hierarchy, and
motion behavior for the supervised Device Reality gate.

## Use through controls

Read the receipt with `factory revenue appforge-status`, local MCP tool
`factory.appforge_native_surface_status`, or the matching Graph Ops WebMCP
tool. All three are read-only.

## Source patterns, not dependencies

- [Apple Design System Catalog](https://github.com/mjmirza/apple-design-system):
  treat named Apple components and official links as a reproducible reference;
  fetch any Apple design assets directly under Apple's terms and keep them out
  of this repository.
- [Apple Design Templates](https://github.com/mikonyaa/Apple-Design-Templates):
  the reusable principle is adaptive app shells, system-first behavior,
  accessibility fallbacks, and real-demo evidence. AppForge does not copy its
  code.
- [Glasskit](https://github.com/sahil639/Glasskit):
  custom glass is a deliberate, bounded visual layer—not a default content
  texture.
- [shots](https://github.com/jtholloran/shots):
  screenshot framing and captions are marketing composition, but AppForge
  requires the underlying journey and candidate bindings first.
- [iOS and iPadOS 26 Community](https://github.com/jason-czar/iOS-and-iPadOS-26-Community)
  and [open-source-ios-apps](https://github.com/dkhamsing/open-source-ios-apps):
  useful discovery/reference material only. Evaluate each downstream project’s
  license and provenance before reuse.

Apple guidance remains authoritative and can change. This gate is a local
review aid, not certification or a guarantee of App Store acceptance.
