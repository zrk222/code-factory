# AppForge Surface Integrity

## Ten-second value

AppForge turns a confirmed product/design decision into three reviewable local
receipts before a human collects device evidence or touches App Store Connect:

1. **Native Surface Truth** binds the exact build candidate, confirmed design
   input digest, local Swift source, adaptive-navigation intent, accessibility
   fallbacks, restrained custom-material budget, and screenshot storyboard.
2. **Device-Family Matrix** expands a ready Native Surface receipt into the
   exact iPhone, iPad, Split View, Dynamic Type, Reduce Motion, Reduce
   Transparency, Increase Contrast, and VoiceOver configurations that still
   require supervised physical-device evidence.
3. **Storefront Story Truth** binds every ready Store-media capture to one
   user journey, one story beat, and a reviewed claim posture. Feature and
   measured claims require local evidence references; unsupported high-risk
   claims block instead of slipping into a caption.

Together they make the design path legible:

`confirmed design input -> local Swift surface -> required device proof -> exact screenshot -> reviewed user claim`

## What was borrowed, and what was deliberately not copied

- The Apple design-system catalog inspired the **component/pattern provenance**
  boundary: AppForge records local sources and confirmed intent rather than
  copying or redistributing Apple assets.
- Apple-Design-Templates inspired **adaptive navigation and accessibility
  configuration coverage**, not imported template code.
- Glasskit informed the **custom-material budget**: custom glass is reviewed
  sparingly, while system components remain preferred.
- `shots` inspired **storefront narrative coverage**: screenshots must explain
  a real journey, not decorate a marketing claim.
- Community kits and open-source app catalogs are discovery references only;
  AppForge does not vendor third-party Swift, Figma, device-frame, or Apple
  assets. Each upstream license remains independent.

## Operating order

```powershell
factory revenue appforge-native-surface --root . --candidate candidate.json --contract native-surface-contract.json --evidence native-surface-evidence.json --out .factory/appforge/native-surface.json --json
factory revenue appforge-surface-matrix --root . --candidate candidate.json --native-surface .factory/appforge/native-surface.json --out .factory/appforge/surface-matrix.json --json
factory revenue appforge-storefront-story --root . --candidate candidate.json --store-media .factory/appforge/store-media.json --contract storefront-story-contract.json --evidence storefront-story-evidence.json --out .factory/appforge/storefront-story.json --json
```

Read the same bounded state through local MCP or progressive WebMCP:

- `factory.appforge_native_surface_status`
- `factory.appforge_surface_matrix_status`
- `factory.appforge_storefront_story_status`

## Human control and claim boundaries

- The native gate uses static source observations. It does **not** build,
  render, run a simulator, operate a device, download assets, access
  credentials, or contact Apple.
- The matrix creates a plan only. A listed configuration is not passed until a
  matching supervised Device Reality receipt is reviewed.
- The storefront gate validates scene coverage and local file references. It
  does **not** prove what pixels depict or that an external reference
  substantively supports a claim.
- None of these receipts uploads media, submits a build, changes App Store
  Connect, or establishes TestFlight, App Review, policy certification, or
  Apple approval.

## Why this is an AppForge hybrid, not a style importer

Design quality alone cannot prove a release path. Release automation alone
cannot prove that an adaptive layout, accessibility setting, screenshot, and
caption all describe the same exact build. Surface Integrity keeps the useful
bridge: a human can see what the app promises, what the source declares, what
must be proven on actual devices, and what the storefront claims—all before
the final external handoff.
