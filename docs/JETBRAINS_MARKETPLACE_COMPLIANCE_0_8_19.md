# FactoryLine 0.8.19 — Marketplace compliance checklist

**Candidate state:** local candidate only. This evidence record reduces
avoidable review risk; it does not claim Marketplace approval, compatibility
across untested products, or JetBrains' review timing.

Official sources: [Approval Guidelines](https://plugins.jetbrains.com/docs/marketplace/jetbrains-marketplace-approval-guidelines.html),
[upload guidance](https://plugins.jetbrains.com/docs/marketplace/uploading-a-new-plugin.html),
[listing guidance](https://plugins.jetbrains.com/docs/marketplace/best-practices-for-listing.html),
and [build-number rules](https://plugins.jetbrains.com/docs/intellij/build-number-ranges.html).

| Applicable requirement / risk | Candidate evidence | Status / release rule |
| --- | --- | --- |
| New SaaS status must not turn the IDE plugin into an identity, billing, or credential integration. | The native action runs only `factory saas status --root <project> --json`; Graph Ops projects hash-valid receipt metadata. Contract verification occurs in the separately installed local CLI and rejects raw tokens, secrets, cookies, authorization headers, and code verifiers. | **Local source, command-construction, and unit-test evidence. Provider certification remains out of scope.** |
| Original branding, factual English copy, relevant notes, and distinct identity. | Generated ZIP preflight reads `plugin.xml`, both 40×40 SVG icons, vendor contact, URL, version, and current change notes. | **Local pass requires `guardianReleaseGate`.** Marketplace dashboard text, tags, screenshots, and originality assessment remain external. |
| Compatibility is not merely declared. | Packaged descriptor requires `since-build="252"`, platform/VCS modules, and no speculative upper bound. Plugin Verifier checks the generated ZIP; protected CI checks the sealed artifact across the declared product matrix. | **Current-platform local verification; full matrix requires CI.** |
| No covert data handling or privileged background repair. | Guardian retains bounded aggregate observations in memory. Engineering Judgment reads local CLI JSON only after explicit workspace confirmation. Change Profile routing uses only user-supplied canonical JSON; it does not infer source semantics. | **Static and unit-test evidence; JetBrains may independently assess runtime behavior.** |
| Archive has valid structure and no credential-shaped material. | `marketplacePreflight` checks size, path shape, descriptor, icons, and prohibited credential/source-control-shaped entries in the generated ZIP. | **Local pass requires `guardianReleaseGate`.** |
| License, EULA, vendor, trader, and pricing facts are not misrepresented. | The generated plugin JAR contains the repository's `LICENSE-MIT`, `LICENSE-APACHE`, and `NOTICE` under `META-INF/licenses`; the active descriptor is free and does not advertise future pricing. | **Artifact license notice is locally verified. Vendor-console EULA, Developer Agreement, trader declaration, and any Sales Info remain owner-only external gates.** |
| An earlier binary update must not be bypassed. | `scripts/jetbrains_marketplace_status.py --require-upload-slot` fails closed when `hasUnapprovedUpdate` reports an occupied binary queue. Listing-metadata review remains visible separately and is never presented as approved. The protected workflow seals tag, commit, channel, ZIP SHA-256, and size before the privileged publish job. | **External gate. Do not dispatch while the binary upload slot is occupied.** |

## Approval-guideline evidence map

This is a local evidence map against the March 31, 2026 approval guidance. It
does not substitute for Marketplace review or owner-console declarations.

| Guideline area | What was verified locally | What remains external or non-verifiable locally |
| --- | --- | --- |
| Logo and name | The generated JAR contains two 40×40 SVG icons. The descriptor name is `FactoryLine AI Proof`: Latin characters, 20 characters, and no forbidden `Plugin`, `IntelliJ`, `JetBrains`, or pricing wording. | Marketplace decides distinctiveness and any potential third-party-mark confusion. |
| Vendor and listing copy | Descriptor includes the source URL and vendor email; its English description opens with a factual short summary. Current change notes are feature-specific and have no template placeholders. | Reachability of the email inbox, dashboard tags, screenshots, and final editorial review occur outside this checkout. |
| Archive integrity | `marketplacePreflight` requires the patched descriptor, icons, bundled MIT/Apache/NOTICE texts, safe root layout, no traversal, 400 MiB maximum, and no credential/source-control-shaped entry. | Marketplace automated scanners and manual inspection run after an upload. |
| Compatibility | Descriptor declares `since-build="252"` with no fabricated upper bound. `guardianReleaseGate` runs the IntelliJ test suite and Plugin Verifier on the generated ZIP. | A green local verifier is current-platform evidence only; the protected CI matrix and JetBrains determine broader compatibility. |
| Privacy, telemetry, and performance | A production-source scan finds no `java.net`, `HttpClient`, `Socket`, or `URL` API reference. Guardian, Engineering Judgment, and SaaS Reality status are explicit-confirmation, local observation/read-only surfaces; tests cover command construction, schema rejection, secret rejection, and UI/action registration. | Runtime behavior in every IDE and Marketplace's independent security/performance analysis cannot be proven locally. |
| Product interference | The current feature is navigation/inspection only. The descriptor and reviewer summary state its declared boundary: no alteration of IDE licensing, subscriptions, trials, upgrade flows, indexes, caches, settings, source, VCS, or remote state. | JetBrains assesses actual behavior during review. |
| Legal and commerce | The artifact carries dual-license notices. The active binary states the local proof core is free and contains no checkout or entitlement logic. | Vendor Agreement acceptance, Marketplace EULA selection, trader/non-trader declaration, vendor identity, banking, and any future paid-sales configuration are owner-console responsibilities. |

## Required release receipt

Before submitting `jetbrains-v0.8.19`, retain:

1. `./gradlew guardianReleaseGate` success on the final commit;
2. sealed ZIP tag/commit/SHA evidence and a green compatibility CI matrix;
3. `python scripts/jetbrains_marketplace_status.py --plugin-id 33009 --require-upload-slot --json`
   returning `upload_slot_clear: true`, while separately recording any pending listing metadata;
4. owner confirmation for Vendor profile, EULA, Agreement, trader, and any
   applicable Sales Info; and
5. authenticated Marketplace read-back after upload and after approval.

Local preflight can minimize avoidable hold-ups. JetBrains retains the approval
decision and manual-review timing.
