# MCP and WebMCP

Code Factory exposes the same local proof state through two complementary, read-only surfaces.

## Ten-second value

- **MCP:** an IDE or coding agent can inspect verified local facts through the existing stdio server.
- **WebMCP:** a compatible browser agent can inspect the Graph Ops snapshot already visible to the user.
- **One boundary:** neither surface can execute, approve, publish, deploy, sign, message, read credentials, or grant a connector.

## Local MCP

Run `factory mcp serve --root .` from the workspace and connect the stdio process from the user's chosen MCP client. In addition to the existing proof, graph, intent, verifier, and agent-supervision tools, the server exposes:

- `factory.revenue_status` — hash-verified RevenueForge build and evidence state.
- `factory.revenue_memory` — exact-app, unexpired prior guidance with contradiction quarantine.
- `factory.appforge_status` — hash-verified AppForge design-contract state.
- `factory.oracle_firewall_status` — sealed Oracle Firewall provenance, drift,
  independent challenge, and incident facts.
- `factory.proof_continuity_status` — repository-level audit continuity from
  sealed original intent through later observations; a contradiction reopens the
  chain for human-supervised review and never self-releases work.
- `factory.appforge_oracle_status` — candidate-bound AppForge policy authority
  facts.
- `factory.appforge_device_reality_status` — sealed device-intent and
  supervised-capture receipt facts; never starts a device transport.
- `factory.appforge_release_rehearsal_status` — candidate-bound Fastlane, App
  Store Connect CLI, Cider, Swiftlane, or Zealot rehearsal facts; never invokes a provider, accesses
  credentials, uploads a build, or submits a release.
- `factory.appforge_native_surface_status` — candidate-bound static Swift
  adaptive-surface, accessibility, material-budget, and storyboard state.
- `factory.appforge_surface_matrix_status` — candidate-bound iPhone/iPad and
  accessibility configurations waiting for supervised Device Reality evidence.
- `factory.appforge_storefront_story_status` — candidate-bound screenshot
  story coverage and local claim-reference state.
- `factory.appforge_fastlane_capture_status` — candidate-bound Fastlane
  Snapshot capture contracts. This is local MCP only: Fastlane/Xcode execution
  remains outside the Windows control plane and needs a separately authorized
  macOS/Xcode environment.

Every tool has a strict JSON input schema, a deterministic name, and read-only annotations. Provider credentials and external writes stay outside the server.

## Graph Ops WebMCP

Graph Ops progressively registers the following browser tools through
`document.modelContext` when the browser supports the current WebMCP draft:

1. `factory.graph_summary`
2. `factory.agui_review_events`
3. `factory.next_action`
4. `factory.revenue_status`
5. `factory.appforge_status`
6. `factory.oracle_firewall_status`
7. `factory.appforge_oracle_status`
8. `factory.appforge_device_reality_status`
9. `factory.appforge_release_rehearsal_status`
10. `factory.appforge_native_surface_status`
11. `factory.appforge_surface_matrix_status`
12. `factory.appforge_storefront_story_status`
13. `factory.first_lap_status`

`factory.first_lap_status` is the recommended first discovery call for a new
agent. It exposes only the local First Lap initialization and generated-file
integrity projection already loaded by the page. It never executes journeys,
opens verifier holdouts, changes a mission, or grants approval. The CLI parity
command is `factory first-lap status --root .`.

`factory.agui_review_events` is the compact card/interrupt bridge for Mission
Control. It returns stable, hash-bound controlled events derived from the same
local First Lap status; it does not execute generated UI, retain sessions, or
grant release authority. See [AGUI and MCP2 review surface](AGUI_MCP2.md).

The handlers read only the most recent authenticated snapshot already loaded by the page. They do not make a second request, invoke an execution control, or return the complete graph. Outputs are deliberately bounded and marked read-only plus untrusted-content because project-controlled labels are data, not agent instructions.

Unsupported browsers keep the normal Graph Ops interface. WebMCP is currently a draft Community Group Report, so this integration is progressive enhancement rather than a compatibility promise.

## Safe handoff

1. The user or coding assistant starts in an IDE with local MCP.
2. Graph Ops visualizes the same receipt-backed state and human authorization boundary.
3. A compatible browser agent can ask for a bounded status through WebMCP.
4. Any repair, approval, provider write, or release still uses a separately reviewed, explicit path.

This is a status handoff, not an authority handoff.
