# FactoryLine 0.8.14 — Marketplace compliance checklist

**Candidate state:** local candidate only. This checklist is a release-blocking
record, not a declaration of Marketplace approval. “Pass” means the cited
repository or packaged-artifact condition is deterministically checked;
“external” requires an authenticated Marketplace or JetBrains decision before
publication.

Official policy sources: [Approval Guidelines](https://plugins.jetbrains.com/docs/marketplace/jetbrains-marketplace-approval-guidelines.html),
[upload guidance](https://plugins.jetbrains.com/docs/marketplace/uploading-a-new-plugin.html),
[listing guidance](https://plugins.jetbrains.com/docs/marketplace/best-practices-for-listing.html),
and [build-number rules](https://plugins.jetbrains.com/docs/intellij/build-number-ranges.html).

| Official requirement / review risk | Candidate evidence | Status | Release rule |
| --- | --- | --- | --- |
| Original 40×40 SVG logo that does not use the default template or resemble a JetBrains product logo. | `pluginIcon.svg` and `pluginIcon_dark.svg` each declare `width="40" height="40"`; `marketplacePreflight` requires both packaged files. The logo's originality remains human review. | **Pass locally; external visual judgment** | Do not claim logo approval until Marketplace accepts it. |
| Original, Latin, ≤30-character plugin name with no price, “Plugin”, “IntelliJ”, or JetBrains product name. | Packaged descriptor requires `FactoryLine AI Proof` (20 characters); the static string contains no pricing or prohibited product-name wording. | **Pass locally** | Keep this exact name unless a Marketplace reviewer requests a change. |
| Valid vendor email and website. | Packaged descriptor requires `rkatz22@gmail.com` and `https://github.com/zrk222/code-factory`. Source, license, and issue surfaces are public there. Functional mailbox/site and Vendor profile ownership are not testable from the ZIP. | **Configured locally; external functional/profile check** | Account owner confirms Vendor profile and responsive email before dispatch. |
| Accurate English description, legitimate tags/assets, and no unfair promotion or misleading claims. | Descriptor starts with a factual English summary and names Guardian’s observation-only boundary. `0.8.14` contains no post-success browser-promotion code; preflight rejects inactive pricing/entitlement text and the legacy `star Code Factory` request in the packaged descriptor. Tags, screenshots, custom Marketplace text, and gallery are account-side state. | **Pass for packaged descriptor; external listing fields** | Confirm dashboard tags, screenshots, custom text, and gallery are accurate and current. |
| Relevant change notes only, without template placeholders. | The packaged descriptor has a specific Guardian Core note. Preflight requires the Guardian note and rejects no artifact only when all required metadata checks pass. | **Pass only when `guardianReleaseGate` is green** | Keep only shipped, reviewable behavior in release notes. |
| Links, media, and marketing assets are reachable, relevant, authorized, and non-infringing. | The packaged descriptor contains the public repository URL only; source and license terms are present in the repository. No embedded Marketplace media is shipped in the ZIP. Link reachability, account-side images/video, copyright/trademark clearance, and screen fidelity are external review facts. | **Packaged link configured; external content review** | Check every vendor-dashboard link and media asset before dispatch; remove stale or generic art. |
| Compatibility uses real build numbers, avoids unsupported APIs, and passes Plugin Verifier. | Packaged descriptor requires `since-build="252"` and no invented upper bound. `guardianReleaseGate` requires a compatible Plugin Verifier verdict. The protected workflow verifies the sealed ZIP against IntelliJ IDEA, PyCharm, WebStorm, Rider, CLion, GoLand, RustRover, and DataGrip. | **Local current-platform verifier required; full matrix pending CI** | Do not publish unless the local gate and all sealed-artifact CI matrix jobs are green. |
| Plugin must not significantly degrade IDE performance or disrupt JetBrains functionality. | Guardian samples aggregate values only, bounded to 20 in-memory samples, at three-second cadence; it does not change settings, caches, indexes, plugins, source, VCS, or remote state. | **Code/design boundary verified; external performance review** | No general performance claim. Escalate any reviewer report or regression. |
| Personal/statistical/telemetric data processing needs explicit permission and must not run when unused. | Guardian source and docs limit its data to local in-memory aggregate runtime samples; no project content, paths, plugin list, credentials, or network data are collected. Recording starts only from an explicit button, remains in memory, is bounded, and can be stopped. Separately, any CLI command remains behind workspace confirmation. | **Static implementation/doc evidence; manual review remains external** | Do not add telemetry, upload, or background collection without a new consent design and policy review. |
| Plugin archive is structurally valid and contains no unsafe bundled material. | Preflight checks the generated ZIP path shape, 400 MiB limit, descriptor/icons/action metadata, and rejects `.env`, `.git/`, `id_rsa`, credential, and secret-shaped nested JAR entries. | **Pass only when `guardianReleaseGate` is green** | Treat any preflight failure as stop-ship. |
| Developer EULA/open-source source link, Developer Agreement, and trader declaration. | Repository and `editors/intellij/LICENSE` state MIT OR Apache-2.0; descriptor links the public source. Marketplace EULA selection, Developer Agreement acceptance, and trader/non-trader declaration are vendor-console facts. | **Source terms pass; external account gates unresolved** | Owner must confirm each required Marketplace field before upload/publish. |
| No theme-specific or unrelated feature advertising. | FactoryLine declares a tool window, actions, settings, notifications, and a line marker; it is not a theme plugin and the candidate does not declare a project-type feature to influence recommendations. Marketplace Feature Extractor output remains external. | **Static declaration checked; external extractor/review** | Do not add feature declarations unrelated to evidence review without an explicit product/review pass. |
| Non-incitement/non-discrimination and case-specific Marketplace criteria. | No automated repository check can prove every editorial or case-specific review criterion. The reviewer summary and descriptor were manually kept factual and task-relevant. | **External editorial and policy judgment** | Treat a Marketplace question or reviewer request as release-blocking until resolved. |
| Every update is subject to JetBrains verification and manual approval. | `scripts/jetbrains_marketplace_status.py --require-clear` prevents replacement while an update is pending; the workflow waits on the protected Marketplace environment and preserves candidate/verifier artifacts. | **External approval required** | A successful workflow or upload is not a public-release receipt. Read back the approved/listed version from the Marketplace API/page. |

## Strict dispatch checklist

Before dispatching `Publish JetBrains Marketplace plugin` for
`jetbrains-v0.8.14`, record all of the following:

1. `./gradlew guardianReleaseGate` is green on the final commit.
2. `python scripts/jetbrains_marketplace_status.py --plugin-id 33009 --require-clear --json`
   returns `MARKETPLACE_UPDATE_CLEAR`.
3. The Vendor account confirms EULA/license link, Developer Agreement,
   trader status, and any applicable Vendor details.
4. The immutable tag resolves to that exact verified commit.
5. After dispatch, the sealed candidate and all eight compatibility jobs are
   green before the protected publish job is approved.
6. After upload, Marketplace lists and approves 0.8.14. Until then, report
   the candidate as pending or blocked, never live.

JetBrains alone determines manual review timing and outcome. This repository
can remove avoidable local defects; it cannot certify external approval.
