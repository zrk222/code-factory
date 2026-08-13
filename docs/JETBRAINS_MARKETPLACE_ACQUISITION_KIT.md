# FactoryLine AI Proof: Marketplace Acquisition Kit

This is the ready-to-review listing and measurement package for Marketplace
plugin `33009`. It improves the path from evaluation to first local proof; it
does not assert downloads, conversion, time savings, or productivity that has
not been observed.

## Listing copy for the approved update

**Name**

`FactoryLine AI Proof`

**Preview (the first 40 characters matter)**

`Verify AI code before you ship.`

**Description**

> Turn one outcome into a local MVP, then see exactly what is proved before
> you ship. FactoryLine keeps requirements, tests, policies, receipts, and
> Graph Ops in your workspace for inspection.
>
> **Why pay for opaque app generators?** Create a reviewable MVP starting
> state in minutes—with local receipts, a clear proof path, and an output you
> can extend when you are ready. A starter is not called production-ready until
> product-specific proof exists.
>
> **Start in two minutes**
>
> 1. In your IDE, open **Tools | FactoryLine | Run First Proof** and confirm
>    the workspace.
> 2. From the same workspace, run `factory mvp "Build an approval tracker" --root .`.
> 3. Run `factory studio --root .\my-mvp`, open **Graph Ops**, and inspect the
>    fact-derived next action. Graph Ops is read-only: it cannot execute,
>    approve, publish, deploy, sign, message, access credentials, or grant
>    connectors.
> 4. If you have a PRD, run `factory prd grill PRD.md --root .` before
>    optimization or compilation. It writes a capped, source-bound question
>    sheet with answer stubs; it never rewrites the PRD or starts a build.
>
> **Use it when you need to:**
>
> - start an inspectable MVP from a plain-language outcome;
> - find requirements without verified completion evidence;
> - understand which prior read-only proof may be reused or must rerun;
> - clarify the next unresolved PRD decisions before a scaffold compounds them;
> - record paired time, token, and cost observations without inferred savings.
> - keep AI-review suggestions separate from a neutral, commit-bound proof
>   walkthrough in a GitHub pull request. The optional workflow can coexist
>   with CodeRabbit or another reviewer; it does not require their account,
>   import AI comments as proof, approve, or merge.
>
> **Useful for a first MVP, a careful code review, and a team workflow:**
> start from an outcome, inspect the evidence behind a change, recover the
> fact-derived next step after a diff, and keep supervision plus measured
> observations explicit.
>
> The plugin asks before it runs a command. It does not upload project files or
> receipts, store API keys, sign artifacts, or decide that a release is ready.
> After successful local work, it may offer an optional **Star Code Factory**
> action once per installed plugin version; selecting it opens only the public
> repository and sends no workspace data.
> Works with IntelliJ IDEA, PyCharm, WebStorm, Rider, CLion, GoLand, RustRover,
> and DataGrip from the 2025.2 platform baseline.

**Accurate tags to select when offered by the vendor UI**

`AI`, `Code Quality`, `Code Tools`, `Productivity`, `Testing`

Do not add language, cloud, autonomous-agent, security, or framework tags
unless the published plugin actually exposes that Marketplace category.

## Product-tour assets

The checked-in images below are actual Factory Studio captures from the shipped
0.24.2 codepath. They are product-tour assets for GitHub, PyPI, and the public
landing page; they are **not** JetBrains Marketplace screenshots because they
do not show a JetBrains IDE.

| Asset | Demonstrates | Public-surface caption |
| --- | --- | --- |
| [`factory-studio-mvp-1280x800.png`](assets/marketplace/factory-studio-mvp-1280x800.png) | Outcome-first MVP → professional-proof progression, explicit authority boundary | `Actual Factory Studio: describe an outcome, get a local MVP.` |
| [`graph-ops-studio-1280x800.png`](assets/marketplace/graph-ops-studio-1280x800.png) | Unified Graph Ops, counted evidence, one fact-derived next action, read-only boundary | `Actual Graph Ops: see the local proof path without executing it.` |

For Marketplace itself, follow the IDE-native capture sequence in the
[Screenshot Brief](JETBRAINS_MARKETPLACE_SCREENSHOTS.md). The image set must
be recaptured in a supported JetBrains IDE after the visible plugin UI changes.

## First-use funnel

| Moment | User action | Expected local result | Boundary to preserve |
| --- | --- | --- | --- |
| Evaluate | Install from Marketplace | Plugin appears under **Tools | FactoryLine** | Installation does not grant filesystem export, credential, or release authority. |
| Activate | Run **Run First Proof** | A confirmed `factory doctor --json` result is shown locally | The user can decline; no command then runs. |
| Clarify | Run `factory prd grill PRD.md --root .` | A local, source-bound question sheet with answer stubs | It does not rewrite the PRD, invent answers, or authorize implementation. |
| Create | Run `factory mvp` | A contained `my-mvp` workspace is generated | A starter is not certified production-ready. |
| Understand | Open Studio → **Graph Ops** | Local requirements, slices, mission, proof, and gate state are visualized | Graph Ops remains read-only. |
| Improve | Record paired observations | Time/token/cost fields stay unknown until measured | No modeled productivity or conversion claim is emitted. |
| Review remotely | Add the optional GitHub Proof Review workflow | One neutral Check plus a stable, commit-bound proof walkthrough can sit beside CodeRabbit or another reviewer | It uses no vendor credential or comment as proof and cannot approve or merge. |

## Measurement protocol

Capture a baseline immediately before an approved listing change, after
approval, then at day 7 and day 30:

```powershell
python scripts/jetbrains_marketplace_status.py --plugin-id 33009 --json
python scripts/jetbrains_marketplace_measurement.py --json
```

The checked-in public baseline is 46 downloads on 2026-08-04. The measurement tool reports an observed download delta only. It deliberately leaves conversion rate and causal uplift unavailable until Marketplace impressions/page views or controlled attribution data exist.

Record a rating count and support issues alongside the output when the vendor
dashboard exposes them. Never use repository traffic, CI runs, or product
savings receipts as a proxy for Marketplace conversion.

## Launch sequencing

1. Wait for `MARKETPLACE_UPDATE_CLEAR`; the current pending update may not be
   replaced.
2. Apply the listing copy in the vendor UI or a newly approved package, then
   attach IDE-native screenshots in the stated order.
3. Confirm all links, the free-through-2026 notice, tags, media, compatibility,
   listed version, and public download total on the Marketplace page.
4. Publish the observed baseline/approval/day-7/day-30 report with unknowns
   intact; do not claim that a particular asset caused any change.

All features remain free through December 31, 2026. The $4.95 USD monthly price
is planned for January 1, 2027, subject to JetBrains paid-plugin approval. See
the [2027 monetization runbook](JETBRAINS_MONETIZATION_2027.md).
