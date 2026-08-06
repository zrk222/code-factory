# FactoryLine AI Proof: January 1, 2027 Monetization Runbook

## Decision record

FactoryLine AI Proof remains free through **December 31, 2026**. The paid
Marketplace release is planned for **January 1, 2027** at exactly **USD 4.95 per
month**. The monthly price is owner-approved. It is not the current Marketplace
price and must not be shown as active before JetBrains approves the paid release.

The launch model is **paid**, not freemium. Version `0.8.1` remains the current
planned free Marketplace release. Paid version `2027.1.0` requires either an
active 30-day trial or a valid Marketplace license. The repository continues
under `MIT OR Apache-2.0`; users may inspect and build the source themselves.

The machine-readable source of truth is
[`JETBRAINS_MONETIZATION_2027.json`](JETBRAINS_MONETIZATION_2027.json). Paid mode
is `human_controlled`: automation may validate and package it but may not activate
sales, banking, Product Code registration, or Marketplace approval.

## Customer-facing notice

Use this text on the Marketplace listing, README, release notes, and upgrade FAQ:

> **Free through December 31, 2026.** FactoryLine AI Proof becomes a paid
> JetBrains Marketplace plugin on January 1, 2027 at **$4.95 USD per month**,
> subject to Marketplace approval. New users will receive a planned 30-day trial.
> Version 0.8.1 and the open-source repository remain available; the 2027.1.0
> Marketplace update requires a valid trial or paid license. This change adds no
> telemetry, source upload, credential storage, signing authority, or automatic
> release authority.

Do not use fake scarcity, a crossed-out invented price, or language implying the
price is already active. Taxes and currency conversion are determined by
JetBrains at checkout. Refund and billing claims must link to the terms JetBrains
actually approves.

## Product and pricing fields

| Field | Launch value | State |
|---|---:|---|
| Monthly price | USD 4.95 | owner-approved |
| Effective date | 2027-01-01 | owner-approved |
| Trial | 30 days | planned; confirm in Sales Info |
| Annual price | not selected | leave disabled unless separately approved |
| Community programs | not selected | annual billing is required before enabling |
| Product Code | `PFACTORYLINE` | proposed; confirm availability and registration |
| Paid release | `2027.1.0` | staged |
| Release date | `20270101` | staged |
| Release version | `20271` | staged |
| Paid descriptor `optional` | `false` | staged paid model |

The Product Code is difficult to change after sales begin. Confirm
`PFACTORYLINE` with JetBrains before it enters the active descriptor.

## What customers keep

- All functionality shipped in free version `0.8.1` remains usable under the
  terms that applied to that artifact.
- The public source remains available under the repository license.
- Local-only execution, explicit workspace confirmation, output redaction, and
  the no-upload privacy boundary remain unchanged.
- Existing receipts and savings data remain local and readable.

The Marketplace should not silently auto-upgrade an unlicensed user into a
non-working build. Test upgrade, downgrade, trial-expiry, and offline-license
paths before release and explain the result in release notes.

## Technical implementation contract

Do not add `<product-descriptor>` to active `plugin.xml` during the free period.
The staged descriptor is at
`editors/intellij/monetization/plugin-product-descriptor-2027.xml`.

Before paid release:

1. Register the Product Code and replace the staged value only if JetBrains
   assigns a different code.
2. Change the plugin version to `2027.1.0` so it aligns with release version
   `20271`.
3. Add the registered product descriptor to active `plugin.xml`.
4. Implement JetBrains `LicensingFacade` verification. An uninitialized facade
   is **unknown**, not unlicensed. Do not deny access until initialization is
   complete.
5. Limit checks to startup and a small number per day; do not create a CPU-heavy
   polling loop.
6. Exercise licensed, active-trial, expired-trial, unlicensed, signed offline
   license, invalid license, and uninitialized-facade states.
7. Verify that no private signing key or Marketplace token enters the plugin.
8. Build and test the paid artifact on the Marketplace demo instance before the
   production upload.

## Marketplace pending-update clearance

As of 2026-08-01, the public API reports `approve:false` and
`hasUnapprovedUpdate:true` for plugin `33009`, while version `0.7.1` itself is
approved and listed. This means listing metadata is still pending; it is not safe
to submit another update blindly.

Check it with:

```powershell
python scripts/jetbrains_marketplace_status.py --plugin-id 33009 --require-clear --json
```

Exit `0` with `MARKETPLACE_UPDATE_CLEAR` is the publication gate. Exit `3` with
`MARKETPLACE_UPDATE_PENDING` means inspect the vendor dashboard for reviewer
feedback. If there is no feedback and the state persists beyond JetBrains' stated
two-business-day review window, send the prepared evidence below to
`marketplace@jetbrains.com` after owner approval:

- plugin ID and public URL;
- pending update ID or vendor-dashboard screenshot;
- submission timestamp and current API JSON;
- requested action: approve, reject with feedback, or remove the stale draft;
- confirmation that no new upload should replace the pending item.

## Timeline

### Now through September 30, 2026

- Clear the current unapproved listing update.
- Publish 0.8.1 as the current free activation release only after clearance.
- Replace concept art with real IDE screenshots and record the new baseline.
- Keep the $4.95 notice visible.

### October 1-31, 2026

- Select trader status and complete vendor/trader/banking information.
- Confirm the paid model and `PFACTORYLINE` Product Code with JetBrains.
- Decide whether to add annual billing and community programs; monthly pricing
  stays $4.95 regardless.

### November 1-30, 2026

- Implement and test the license state machine on a dedicated branch.
- Create `2027.1.0` release notes, upgrade FAQ, and support macros.
- Test the complete purchase/trial/expiry flow on Marketplace Demo.

### December 1-15, 2026

- Re-run all Kotlin tests, plugin packaging, Plugin Verifier, compatibility
  matrix, license mutations, and clean-install/upgrade/downgrade tests.
- Submit paid Sales Info and the paid binary early enough for review and fixes.

### December 16-31, 2026

- Freeze paid release inputs and verify all G1-G9 evidence receipts.
- Confirm listing price, trial, terms, screenshots, support contact, and release
  schedule in the vendor dashboard.
- Do not activate early. If approval is incomplete, remain free and move the
  effective date; do not strand users.

### January 1, 2027

- Owner verifies the exact paid artifact, tag, Product Code, price, and Sales
  Info, then approves activation.
- Confirm public API/page show `2027.1.0`, Paid, approved, and listed before any
  announcement.
- Record downloads, trials, purchases, refunds, ratings, and support volume as
  observed values. Do not claim conversion lift without impressions and a valid
  baseline.

## Release commands and receipts

```powershell
python scripts/jetbrains_marketplace_status.py --plugin-id 33009 --require-clear --json
python -m pytest -q tests/test_jetbrains_marketplace_status.py tests/test_publication_metadata.py tests/test_jetbrains_release_artifact.py
Set-Location editors/intellij
.\gradlew.bat check buildPlugin verifyPlugin marketplacePreflight
```

The paid release also requires the eight-product compatibility workflow and the
protected immutable-tag publication workflow. Upload success is not approval;
only the public plugin and version APIs showing approved/listed establish release.

## Go-live gate

Activation is blocked until every gate in the JSON manifest is `verified` with a
dated evidence reference:

1. no pending earlier Marketplace update;
2. trader and banking details verified;
3. Product Code registered;
4. license implementation and state tests green;
5. paid ZIP sealed and independently verified;
6. Sales Info submitted with $4.95 monthly price and trial;
7. paid binary and model approved by JetBrains;
8. public price notice, FAQ, and terms live;
9. named support and rollback owner ready.

## Rollback and customer protection

- Before public approval: withdraw or correct the draft through the vendor
  dashboard; do not retag an immutable release.
- After approval but before sales: contact Marketplace Support for payment-model
  correction and keep 0.8.1 installation instructions available.
- After sales begin: do not remove paid access or alter Product Code unilaterally.
  Coordinate any rollback, refund, or entitlement repair with JetBrains and
  publish a customer notice.
- A failed license initialization must not be treated as piracy. Preserve a
  recoverable retry/support path and never delete local receipts or projects.

Support owner: FactoryLine vendor account. Public contact:
`rkatz22@gmail.com`. No support response time is promised until an explicit SLA
is approved.
