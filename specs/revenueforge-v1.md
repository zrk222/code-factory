# Spec: revenueforge-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Generate deterministic, reviewable iOS monetization scaffolds and post-launch growth proposals from one human-reviewed product manifest while keeping all provider writes and consequential actions outside Code Factory authority.

### Requirements (EARS)

- The system shall emit `REVENUEFORGE_MANIFEST_VALIDATED` only when one bounded products manifest declares unique products, entitlements, compliant paywall facts, HTTPS legal links, and linked purchase-history dataflow. (REQ-RF-001)
- When all deterministic gates pass, the system shall emit `REVENUEFORGE_BUNDLE_WRITTEN` and atomically write StoreKit 2, SwiftUI paywall, entitlement-server, privacy, review-note, dataflow, receipt, and HTML evidence artifacts below the workspace. (REQ-RF-002)
- The system shall emit `REVENUEFORGE_DARK_PATTERN_REJECTED` for countdown, false-scarcity, hidden-cancel, or preselected-upsell declarations and shall emit `REVENUEFORGE_PAYMENT_LANE_REJECTED` for ad SDK, crypto, or alternative-payment declarations. (REQ-RF-003)
- The system shall emit `REVENUEFORGE_SERVER_SCAFFOLD_WRITTEN`, store a server scaffold that calls Apple's `SignedDataVerifier.verifyAndDecodeNotification` before the entitlement transition, and select exactly one of two environment-specific database names: sandbox or production. (REQ-RF-004)
- The system shall emit `REVENUEFORGE_PAYWALL_SCAFFOLD_WRITTEN` and store a paywall scaffold containing Restore Purchases, value, price, duration, Privacy Policy, Terms of Use, exactly one primary purchase action, pending-state visibility, and zero generated dark patterns. (REQ-RF-005)
- The system shall emit `REVENUEFORGE_PHASE8_PLANNED` for at most three Product Page Optimization treatments per experiment and mark experiment promotion, offer send, rating-response publication, pricing, and provider writes as human-required or unavailable. (REQ-RF-006)
- The system shall emit `REVENUEFORGE_BENCHMARK_WITHHELD` below 20 distinct contributing apps and shall emit `REVENUEFORGE_BENCHMARK_PUBLISHED` only at or above that boundary. (REQ-RF-007)
- When Graph Ops reads at most 100 generated receipts, the system shall emit `GRAPH_OPS_REVENUEFORGE_READ_ONLY`, display readiness facts and claim boundaries, and expose zero provider-write controls. (REQ-RF-008)
- The system shall emit `REVENUEFORGE_PATH_REJECTED` for workspace escapes, reject inputs above 1 MiB, and write no credential, private key, receipt body, customer identity, or provider token. (REQ-RF-009)
- The system shall emit `REVENUEFORGE_GATES_BLOCKED` when any required gate fails and shall return a claim boundary describing output as scaffold and local evidence, never Apple approval, legal advice, deployed-server proof, observed conversion, revenue lift, or production readiness. (REQ-RF-010)

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Manifest produces a bounded monetization bundle
  Given a complete human-reviewed products manifest
  When the system builds the bundle
  Then markers include `REVENUEFORGE_MANIFEST_VALIDATED` and `REVENUEFORGE_BUNDLE_WRITTEN`
  And all provider-write authority remains false

Scenario: Manipulative paywall input is rejected
  Given a paywall declares a countdown
  When the system validates the manifest
  Then the marker is `REVENUEFORGE_DARK_PATTERN_REJECTED`

Scenario: Server evidence is verified before use
  Given an App Store Server Notification v2 signed payload
  When the generated server receives it
  Then the marker is `REVENUEFORGE_SERVER_SCAFFOLD_WRITTEN`
  And the verified notification enters the entitlement transition
  And exactly one database name is selected: sandbox or production

Scenario: Paywall contains the complete disclosure surface
  Given a validated product manifest
  When the system stores a paywall scaffold
  Then the marker is `REVENUEFORGE_PAYWALL_SCAFFOLD_WRITTEN`
  And the paywall contains Restore Purchases, value, price, duration, Privacy Policy, Terms of Use, exactly one primary purchase action, and pending-state visibility
  And the paywall contains zero generated dark patterns

Scenario: Small fleet cells remain private
  Given nineteen distinct app records
  When the system computes a fleet benchmark
  Then the marker is `REVENUEFORGE_BENCHMARK_WITHHELD`
  And no median is published

Scenario: Every requirement has an observable validator marker
  Given the monetization contract
  When strict validator mutation runs
  Then markers include `REVENUEFORGE_MANIFEST_VALIDATED`, `REVENUEFORGE_BUNDLE_WRITTEN`, `REVENUEFORGE_DARK_PATTERN_REJECTED`, `REVENUEFORGE_PAYMENT_LANE_REJECTED`, `REVENUEFORGE_SERVER_SCAFFOLD_WRITTEN`, `REVENUEFORGE_PAYWALL_SCAFFOLD_WRITTEN`, `REVENUEFORGE_PHASE8_PLANNED`, `REVENUEFORGE_BENCHMARK_WITHHELD`, `REVENUEFORGE_BENCHMARK_PUBLISHED`, `GRAPH_OPS_REVENUEFORGE_READ_ONLY`, `REVENUEFORGE_PATH_REJECTED`, and `REVENUEFORGE_GATES_BLOCKED`
```

## SHOULD - Technical

- Use one normalized content hash as the cross-artifact source of truth.
- Prefer Apple's official App Store Server Library in generated server scaffolds.
- Keep Android policy and billing as a distinct future ruleset, never inferred from Apple rules.

## SHOULD NOT - Non-goals

- Access or store Apple credentials.
- Make App Store Connect, pricing, experiment, offer, review, publication, or deployment mutations.
- Promise approval or revenue lift.
