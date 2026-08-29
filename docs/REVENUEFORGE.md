# RevenueForge

RevenueForge carries an iOS project from product intent to a reviewable monetization scaffold without giving Code Factory authority over App Store Connect.

```powershell
factory revenue validate --root . --products products.yaml --json
factory revenue build --root . --products products.yaml --out-dir .factory/revenueforge/my-app --json
factory revenue growth-plan --root . --products products.yaml --growth growth.yaml --out .factory/revenueforge/my-app/growth-plan.json --json
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

## Fleet privacy

`factory revenue benchmark` publishes a median only when at least 20 distinct app identifiers contribute. Smaller cells are explicitly withheld.
