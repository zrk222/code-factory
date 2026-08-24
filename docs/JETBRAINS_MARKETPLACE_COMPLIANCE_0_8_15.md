# FactoryLine 0.8.15 — Marketplace compliance checklist

**Candidate state:** local candidate only. This is a release-blocking evidence
record, not a claim of Marketplace approval. “Pass when gated” means the
condition is checked against the generated ZIP; “external” requires an
authenticated Vendor-console or JetBrains determination.

Official sources: [Approval Guidelines](https://plugins.jetbrains.com/docs/marketplace/jetbrains-marketplace-approval-guidelines.html),
[upload guidance](https://plugins.jetbrains.com/docs/marketplace/uploading-a-new-plugin.html),
[listing guidance](https://plugins.jetbrains.com/docs/marketplace/best-practices-for-listing.html),
and [build-number rules](https://plugins.jetbrains.com/docs/intellij/build-number-ranges.html).

| Applicable requirement / risk | Candidate evidence | Status / release rule |
| --- | --- | --- |
| Original 40×40 SVG branding, distinct product name, factual English description, and relevant change notes. | `marketplacePreflight` reads the generated ZIP descriptor and both icons. The descriptor requires `FactoryLine AI Proof`, vendor contact and source URL, and the 0.8.15 Engineering Judgment description. | **Pass when `guardianReleaseGate` is green.** Dashboard tags, screenshots, custom text, and visual originality are external review facts. |
| Compatibility declaration and supported APIs are real. | Packaged `plugin.xml` requires `since-build="252"`, platform and VCS modules, with no speculative upper bound. `guardianReleaseGate` runs Plugin Verifier on the generated ZIP; protected CI additionally verifies the sealed candidate across the declared JetBrains product matrix. | **Current-platform result locally verifiable; full matrix requires CI.** |
| The plugin does not covertly collect or export data, or make unsafe IDE changes. | Guardian’s bounded aggregate local observations stay in-memory and start only by user action. Engineering Judgment reads schema-bound local CLI results after explicit workspace confirmation. Source paths, VCS state, settings, caches, indexes, credentials, network, model calls, repairs, approvals, publication, and deployment are outside their authority. | **Static/source and unit-test evidence; JetBrains may still assess behavior.** |
| Archive structure is valid and free of credential-shaped or unrelated bundled material. | `marketplacePreflight` checks archive size/path shape, descriptor, icons, metadata, and rejects credential-shaped bundle entries. | **Pass when `guardianReleaseGate` is green.** |
| Licensing, Vendor Agreement, Marketplace EULA, trader status, and pricing configuration are correctly represented. | `LICENSE`, `LICENSE-MIT`, `LICENSE-APACHE`, and `editors/intellij/LICENSE` declare the repository terms. The plugin is free; future paid-plan documents are not entitlement code. | **Source terms are inspectable; Vendor-console declarations are external owner gates.** |
| Every update is subject to Marketplace verification/manual approval. | `scripts/jetbrains_marketplace_status.py --require-clear` fails closed when a Marketplace update is pending. The protected workflow seals one ZIP to SHA-256, tag, commit, and channel before the privileged publish job. | **External approval and timing remain JetBrains-only.** Do not dispatch while the status gate is not clear. |

## Strict dispatch receipt

Before submitting `jetbrains-v0.8.15`, retain:

1. `./gradlew guardianReleaseGate` success on the final commit;
2. a sealed-artifact tag/commit/SHA receipt and green compatibility CI matrix;
3. `python scripts/jetbrains_marketplace_status.py --plugin-id 33009 --require-clear --json`
   returning `MARKETPLACE_UPDATE_CLEAR`;
4. account-owner confirmation of Vendor-profile, EULA, Agreement, trader, and
   any applicable sales-information fields; and
5. an authenticated Marketplace read-back after upload, then after approval.

Local evidence reduces avoidable review risk. It cannot guarantee JetBrains'
manual-review outcome or timing.
