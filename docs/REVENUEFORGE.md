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
factory revenue billing-reconcile --root . --products products.yaml --events billing-events.json --out .factory/revenueforge/my-app/billing-ledger.json --json
factory revenue experiment-plan --root . --products products.yaml --experiment experiment.json --out .factory/revenueforge/my-app/experiment-plan.json --json
factory revenue integrity --root . --products products.yaml --ledger .factory/revenueforge/my-app/billing-ledger.json --experiment .factory/revenueforge/my-app/experiment-plan.json --out .factory/revenueforge/my-app/integrity.json --json
factory revenue appforge-design --root . --brief appforge-design-brief.json --out-dir .factory/appforge/design --json
factory revenue app-review-gate --root . --contract app-review-contract.json --evidence app-review-evidence.json --out .factory/appforge/app-review.json --json
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
- **Billing Integrity Ledger** reconciles verified StoreKit, Play Billing, and server observations. Exact retries collapse by idempotency key; conflicts block and suppress grant candidates; refunds and revocations deterministically make a prior entitlement inactive. It stores no customer identity and never grants access.
- **Experiment Guard** compiles a hypothesis, cohort, metric, numeric guardrail, sample bound, and two-or-three-treatment plan. Agent proposals remain `AWAITING_HUMAN_APPROVAL`; separate approval moves them only to `READY_FOR_HUMAN_START`. Starting traffic, changing prices, and promoting a winner remain locked.
- **Revenue Integrity Review** binds the current manifest to ledger and experiment receipts, detects manifest drift, and returns one remediation. Its `READY_FOR_HUMAN_REVIEW` result is local evidence, not a revenue, legal, provider, or App Review claim.

Graph Ops shows these receipts read-only. It offers no button that can purchase, submit, publish, reply to a tester, change price, start an experiment, deploy, or access credentials.

## AppForge Design Director

`appforge-design` makes the human's audience, job, desired emotion, brand direction, and screen goals the source of truth. It writes an iOS storyboard plus a reusable design-director skill spanning seven review disciplines: visual direction, accessibility, SwiftUI design, motion, gestures, performance, and color psychology. A Nanna narrative spine organizes each experience through mission, tension, guidance, agency, transformation, and celebration, while deterministic guardrails prohibit storytelling from hiding price, consequence, system state, cancellation, or recovery.

## AppForge Evidence Kit

`factory revenue evidence-kit` turns one exact candidate plus the approved user-design input into a plain-language worklist and deliberately incomplete, candidate-bound evidence templates. This reduces setup friction without treating placeholders, source code, or agent assertions as proof. See [AppForge Evidence Kit](APPFORGE_EVIDENCE_KIT.md).

The output is a design and review contract, not a rendered app or an accessibility/performance/App Review claim. Device traces, assistive-technology task evidence, and human visual approval remain required.

### App Review rejection-regression gate

`app-review-gate` converts prior real failure classes into a reusable, sanitized stop-ship check. It binds observations to one bundle/version/build/commit and blocks when required device, commerce, design, metadata, privacy, legal, safety, reviewer-access, or export evidence is false, missing, or not a literal boolean `true`. Conditional Apple rules must be classified as required or explicitly not applicable with a named reviewer and rationale; they cannot disappear through omission. This helps improve app design and minimize avoidable App Store rejection risk because source-level correctness can no longer stand in for current-build reviewer-path evidence. It does **not** guarantee Apple approval and never uploads to TestFlight or submits for review.

## Fleet privacy

`factory revenue benchmark` publishes a median only when at least 20 distinct app identifiers contribute. Smaller cells are explicitly withheld.
