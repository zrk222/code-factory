# Spec: revenueforge-evidence-v2
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Convert authorized local purchase, TestFlight, negative-path, and official-policy snapshots into privacy-bounded, hash-sealed operational evidence while preserving human App Store authority.

### Requirements (EARS)

- When a manifest-matching sandbox or TestFlight build supplies 1-500 strictly ordered unique events, the system shall compare exactly seven required lifecycle steps and emit `matched`, `mismatch`, or `unknown` without inference. (REQ-RFE-001)
- When cryptographic verification is absent from transaction or server-notification evidence or a referenced product is absent from the manifest, the system shall emit `REVENUEFORGE_VERIFICATION_MISMATCH` and step status `mismatch`. (REQ-RFE-002)
- When an authorized local TestFlight export supplies at most 1000 records, the system shall emit `REVENUEFORGE_TESTFLIGHT_EVIDENCE_SYNCED`, deduplicate by external-id/build binding, remove identity and signed-payload fields, bind device/OS/app/build facts, and group records by journey without a provider request or reply. (REQ-RFE-003)
- The system shall evaluate exactly ten failure scenarios, shall emit verdict `pass` only when every scenario supplies `observed=true` and `passed=true`, shall emit scenario status `unknown` for absent or malformed evidence, and shall emit verdict `blocked` when any scenario is `fail` or `unknown`. (REQ-RFE-004)
- The system shall accept only `https://developer.apple.com/` policy sources with a retrieval date and a 64-character SHA-256, compare baseline and current hashes, and invalidate only declared rule/app/artifact impacts. (REQ-RFE-005)
- The system shall keep every output inside the workspace, write it atomically, bind it to `receipt_sha256`, and set authority to false for provider writes, credentials, deployment, pricing, experiments, offers, review replies, and publication. (REQ-RFE-006)
- When Graph Ops reads the four receipt families, the system shall emit `GRAPH_OPS_REVENUE_EVIDENCE_READ_ONLY`, project them read-only, and state unknowns or mismatches without claiming Apple approval, legal compliance, production behavior, or revenue. (REQ-RFE-007)
- When a named human promotes an exact-app operational lesson backed by one or more valid RevenueForge receipts, the system shall emit `REVENUEFORGE_EVIDENCE_MEMORY_PROMOTED`, preserve receipt hashes instead of bodies, require an expiry, disable cross-tenant reuse, and quarantine conflicting active decisions during `REVENUEFORGE_EVIDENCE_MEMORY_QUERIED`. (REQ-RFE-008)
- The system shall make every evidence and design function emit a concise `action_summary` that identifies its action and preserves the boundary between local analysis or artifact writes and locked external provider actions. (REQ-RFE-009)
- When an MCP client requests RevenueForge, exact-app Evidence Memory, or AppForge status, the stdio server shall return schema-bounded, read-only local facts and shall not expose provider credentials or mutation authority. (REQ-RFE-010)
- When Graph Ops runs in a browser implementing the current WebMCP draft, the page shall register exactly four read-only, untrusted-content tools over the already-loaded authenticated snapshot; unsupported browsers shall retain the normal UI and no tool shall execute, approve, publish, deploy, sign, message, access credentials, or grant connectors. (REQ-RFE-011)

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Complete purchase evidence matches the required lifecycle
  Given seven build-bound events in required order
  When purchase replay compares the events with the manifest
  Then all seven steps are `matched`
  And the verdict is `matched`

Scenario: Unverified transaction and undeclared product mismatch
  Given cryptographic verification is absent from a transaction or server-notification event
  And its product is absent from the manifest
  When purchase replay compares the event
  Then the marker is `REVENUEFORGE_VERIFICATION_MISMATCH`
  And the step status is `mismatch`

Scenario: TestFlight export becomes a privacy-bounded inbox
  Given an authorized local TestFlight export contains 1000 records
  When the evidence inbox normalizes the export
  Then the marker is `REVENUEFORGE_TESTFLIGHT_EVIDENCE_SYNCED`
  And records are deduplicated by external-id/build binding
  And identity and signed-payload fields are absent
  And device, OS, app, build, and journey facts remain

Scenario: Missing failure evidence cannot become green
  Given one observed passing scenario and nine absent scenarios
  When the failure matrix is evaluated
  Then one scenario is `pass`
  And nine scenarios are `unknown`
  And the verdict is `blocked`

Scenario: Policy drift remains impact-scoped
  Given two registered official Apple sources
  And exactly one source hash changes
  When policy watch compares the snapshot
  Then only the changed source's declared rules, apps, and artifacts are affected

Scenario: Policy source input is exact
  Given a policy source does not start with `https://developer.apple.com/`
  Or its SHA-256 is not 64 hexadecimal characters
  When policy watch validates the source
  Then the source is rejected

Scenario: Outputs preserve human authority
  Given any evidence command
  When it writes a receipt
  Then the receipt remains inside the workspace
  And `receipt_sha256` is present
  And provider writes, credentials, deployment, pricing, experiments, offers, review replies, and publication authority are false

Scenario: Graph Ops remains evidence-only
  Given replay, TestFlight, failure-matrix, and policy-drift receipts
  When Graph Ops reads the four receipt families
  Then the marker is `GRAPH_OPS_REVENUE_EVIDENCE_READ_ONLY`
  And the receipts are projected read-only
  And unknowns and mismatches are visible
  And no Apple approval, legal compliance, production behavior, or revenue claim is emitted

Scenario: Evidence Memory cannot silently reuse a contradiction
  Given a named human promotes two unexpired exact-app lessons backed by valid RevenueForge receipt hashes
  And each lesson has an expiry
  And cross-tenant reuse is false
  And the lessons have different decisions for the same journey
  When the lessons are promoted
  Then the marker is `REVENUEFORGE_EVIDENCE_MEMORY_PROMOTED`
  When `REVENUEFORGE_EVIDENCE_MEMORY_QUERIED` retrieves the lessons
  Then both lessons are quarantined
  And the next action is human contradiction review

Scenario: MCP and WebMCP preserve the same authority boundary
  Given RevenueForge and AppForge receipts are present in the local workspace
  When an MCP client reads their status
  Or a compatible browser agent reads the current Graph Ops snapshot
  Then the returned facts are bounded and read-only
  And project-controlled content is marked untrusted in WebMCP
  And no execution, approval, publication, deployment, signing, messaging, credential, or connector authority is granted
```

## SHOULD NOT - Non-goals

- Fetch Apple data or policy pages in the deterministic core.
- Store tester identity, signed payloads, JWS values, secrets, or provider tokens.
- Treat a missing observation, changed source, or scaffold as production proof.
- Treat draft WebMCP availability as a browser-compatibility guarantee or an authority channel.
