# RevenueForge

RevenueForge carries an iOS project from product intent to a reviewable monetization scaffold without giving Code Factory authority over App Store Connect.

```powershell
factory revenue validate --root . --products products.yaml --json
factory revenue build --root . --products products.yaml --out-dir .factory/revenueforge/my-app --json
factory revenue growth-plan --root . --products products.yaml --growth growth.yaml --out .factory/revenueforge/my-app/growth-plan.json --json
factory revenue replay --root . --products products.yaml --events purchase-events.json --out .factory/revenueforge/my-app/replay.json --json
factory revenue testflight-sync --root . --feedback testflight-feedback.json --out .factory/revenueforge/my-app/testflight-inbox.json --json
factory revenue failure-matrix --root . --products products.yaml --evidence failure-evidence.json --out .factory/revenueforge/my-app/failure-matrix.json --json
factory revenue policy-watch --root . --registry apple-policy-registry.json --snapshot apple-policy-snapshot.json --out .factory/revenueforge/my-app/policy-drift.json --json
factory revenue memory-promote --root . --entry approved-lesson.json --out .factory/revenueforge/memory/restore-lesson.json --json
factory revenue memory-query --root . --app-id com.example.app --journey restore --json
factory revenue appforge-design --root . --brief appforge-design-brief.json --out-dir .factory/appforge/design --json
```

One `products.yaml` drives:

- a StoreKit 2 `RevenueKit` scaffold with verified transactions, pending-state handling, current entitlements, and Restore Purchases;
- a SwiftUI paywall that presents benefits, price, duration, legal links, and one primary CTA;
- an entitlement-server scaffold based on Apple's official Node server library, with JWS verification before decoding and separate sandbox/production stores;
- purchase dataflow, privacy-label input, a counsel-review privacy clause, subscription review notes, and a local HTML evidence page;
- a Phase 8 proposal for Product Page Optimization, custom product pages, governed offers, ratings, ASO, localized pricing, and a separate Android lane.

## Human control boundary

RevenueForge performs no App Store Connect write, purchase, price change, offer send, experiment start, winner promotion, review-response publication, deployment, or credential access. Those actions require authenticated provider state, current policy checks, and a separately authorized human operation.

The generated receipt proves local scaffold content and deterministic checks. It is not App Review approval, deployed-server proof, legal advice, an observed conversion result, or a revenue claim.

## Operational evidence

- **Purchase Reality Replay** compares an ordered, build-bound sandbox or TestFlight event export with the required paywall → verified transaction → verified notification → entitlement → restart → restore lifecycle. Missing evidence remains `unknown`; inconsistent evidence is `mismatch`.
- **TestFlight Evidence Inbox** normalizes an authorized local export of feedback, screenshots, and crashes. It deduplicates records, removes identity fields, binds findings to build/device/OS/app versions, and groups issues by purchase journey. It does not call App Store Connect.
- **Monetization Failure Matrix** requires observed results for cancellation, pending, unverified transactions, empty restore, duplicate/out-of-order notifications, refund/revocation, retry/grace, offline stale entitlement, and storefront/price mismatch. Every applicable scenario must pass before the matrix can be green.
- **Policy Drift Watch** compares reviewed official-Apple source hashes. A changed source invalidates only its declared rule/app/artifact bindings and requires human reassessment; hash drift is not itself a legal or compliance conclusion.
- **Evidence Memory** promotes only named-human-approved lessons backed by valid RevenueForge receipts. Retrieval is exact-app, exact-journey, expiry-aware, and cross-tenant disabled; conflicting active decisions are quarantined. A retrieved lesson recommends the next check but never substitutes for current-build evidence.

Graph Ops shows these receipts read-only. It offers no button that can purchase, submit, publish, reply to a tester, change price, start an experiment, deploy, or access credentials.

## AppForge Design Director

`appforge-design` makes the human's audience, job, desired emotion, brand direction, and screen goals the source of truth. It writes an iOS storyboard plus a reusable design-director skill spanning seven review disciplines: visual direction, accessibility, SwiftUI design, motion, gestures, performance, and color psychology. A Nanna narrative spine organizes each experience through mission, tension, guidance, agency, transformation, and celebration, while deterministic guardrails prohibit storytelling from hiding price, consequence, system state, cancellation, or recovery.

The output is a design and review contract, not a rendered app or an accessibility/performance/App Review claim. Device traces, assistive-technology task evidence, and human visual approval remain required.

## Fleet privacy

`factory revenue benchmark` publishes a median only when at least 20 distinct app identifiers contribute. Smaller cells are explicitly withheld.
