# JetBrains Marketplace Growth and Release Guide

## Public listing

FactoryLine is public as Marketplace plugin `33009`:
<https://plugins.jetbrains.com/plugin/33009-factoryline>.

The public [measurement baseline](JETBRAINS_MARKETPLACE_MEASUREMENT.json) is
46 downloads on 2026-08-04. Treat later totals as observed growth, not proof that
a particular copy or screenshot change caused it. The Marketplace API also showed
an unapproved update at that snapshot, so inspect the vendor dashboard before
submitting or replacing anything pending.

## Conversion-focused listing

- **Name:** `FactoryLine AI Proof`
- **Preview:** `Catch hollow tests before review.`
- **Tags:** `AI`, `Code Quality`, `Code Tools`, `Productivity`, `Testing`
- **Source:** <https://github.com/zrk222/code-factory>
- **License:** repository `MIT OR Apache-2.0` terms
- **Getting started:** `Tools | FactoryLine | Run First Proof`

The name stays distinct from the existing Marketplace product named Code Factory.
The first sentence is short enough to carry the full preview outcome. The packaged
descriptor is the source of truth for the full description and change notes.

Use only tags offered by the Marketplace vendor UI that accurately match shipped
behavior. Do not repeat keywords or select unrelated languages and frameworks.

The paste-ready [Marketplace Acquisition Kit](JETBRAINS_MARKETPLACE_ACQUISITION_KIT.md)
contains the two-minute first-use path, approved copy, public product-tour assets,
and the distinction between those web assets and required IDE-native Marketplace
screenshots.

All shipped features remain free through December 31, 2026. The owner-approved
future price is **USD 4.95 per month**, planned for January 1, 2027 with a 30-day
trial, subject to JetBrains approval. The payment-model change requires paid-plugin
onboarding, a registered Product Code, license checks, advance user notice, and
verified Sales Info. The price is about 12.54% below the recorded USD 5.66 sample
average; that comparison may drift, but the $4.95 owner decision does not. See the
[pricing benchmark](JETBRAINS_PRICING_BENCHMARK.json) and the complete
[2027 monetization runbook](JETBRAINS_MONETIZATION_2027.md).

Use the actual Factory Studio product-tour assets on GitHub, PyPI, and the public
landing page. For Marketplace media, replace concept art with the IDE-native
sequence in [JetBrains Marketplace Screenshot Brief](JETBRAINS_MARKETPLACE_SCREENSHOTS.md).
Keep the strongest first-use screenshot first. Add a short product video only
after it shows the same real workflow without stale metrics.

## Artifact gate

Run this before any upload:

```powershell
Set-Location editors/intellij
.\gradlew.bat check buildPlugin verifyPlugin marketplacePreflight
```

`marketplacePreflight` inspects the generated ZIP, including Marketplace metadata,
icons, and change notes. Compatibility is verified across IntelliJ IDEA, PyCharm,
WebStorm, Rider, CLion, GoLand, RustRover, and DataGrip from the 2025.2 platform
baseline forward.

## Protected publication

1. Confirm the vendor dashboard has no update that would be unintentionally
   replaced. Resolve any pending JetBrains feedback first.
   `python scripts/jetbrains_marketplace_status.py --plugin-id 33009 --require-clear --json`
   must return `MARKETPLACE_UPDATE_CLEAR`.
2. Merge the tested release commit to `main`.
3. Create the immutable tag matching the plugin version, currently
   `jetbrains-v0.8.9` after the previous Marketplace update is clear.
4. Run **Publish JetBrains Marketplace plugin** with that tag and the intended
   channel. The `JETBRAINS_MARKETPLACE_TOKEN` remains scoped to the protected
   `jetbrains-marketplace` environment.
5. The workflow binds the tested ZIP to its SHA-256, size, plugin identity,
   version, tag, commit, and channel before the privileged publish job.
6. Wait for JetBrains approval, then verify the public version, description,
   compatibility, screenshots, pricing, and download total before announcing it.

Upload, workflow success, and public approval are separate states. Do not report a
new version as live until the public Marketplace API and page both show it.

## Growth measurement

Record the following at submission, approval, day 7, and day 30:

```powershell
python scripts/jetbrains_marketplace_status.py --plugin-id 33009 --json
python scripts/jetbrains_marketplace_measurement.py --json
```

- public downloads and absolute delta from 46;
- ratings count and average rating, if present;
- approved public version and approval latency;
- listing page views, installs, and conversion rate when vendor analytics expose them;
- support issues attributable to install or first-proof friction.

Without Marketplace impressions or page views, download conversion and causal
uplift remain unavailable. Never substitute repository traffic or CI runs for
Marketplace acquisition data.
