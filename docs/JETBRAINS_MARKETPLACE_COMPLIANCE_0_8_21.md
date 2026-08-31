# FactoryLine 0.8.21 — JetBrains Marketplace compliance evidence map

**Candidate state:** local candidate only. This map records repository and
package checks that can reduce avoidable review hold-ups. It is not a claim of
Marketplace approval, compatibility in an untested IDE, or review timing.

Official sources: [Approval Guidelines](https://plugins.jetbrains.com/docs/marketplace/jetbrains-marketplace-approval-guidelines.html),
[upload guidance](https://plugins.jetbrains.com/docs/marketplace/uploading-a-new-plugin.html),
[listing guidance](https://plugins.jetbrains.com/docs/marketplace/best-practices-for-listing.html),
and [build-number rules](https://plugins.jetbrains.com/docs/intellij/build-number-ranges.html).

| Requirement or review risk | 0.8.21 evidence | Status and boundary |
| --- | --- | --- |
| The listing must describe actual plugin behavior. | The generated descriptor advertises **AppForge Mission Control**; the plugin registers `OpenAppForgeAction`, the `AppForge` tool-window tab, and `revenue appforge-status`. The tab accepts only the versioned local status projection. | Local source/package test. App Store state remains outside the plugin. |
| Privacy and user permission (guidelines 2.2 and 3.4). | AppForge status reads local receipts after confirmation. Its UI and descriptor say it does not access credentials, upload media, start TestFlight, submit to Apple, or guarantee approval. | This is the plugin's bounded implementation, not a general prohibition on authenticated plugins. Marketplace performs its own review. |
| Archive must be structurally safe and complete. | `marketplacePreflight` inspects the generated ZIP for size, top-level path shape, descriptor identity, icons, dual-license notices, contact URL/email, change notes, and credential-shaped files. | Locally verifiable. |
| Compatibility cannot be inferred from the build machine. | `guardianReleaseGate` runs IntelliJ tests, packages the ZIP, invokes Plugin Verifier, and requires a compatible verdict; protected CI verifies the sealed artifact against the declared product matrix. | Local current-platform proof plus CI matrix; JetBrains decides final compatibility. |
| Marketplace wording and commerce must not mislead users. | Listing uses bounded claims: AppForge can avoid preventable rework and repeat queue cycles; it cannot guarantee Apple approval. The binary remains free and contains no checkout or entitlement logic. | Local descriptor evidence. Vendor-console EULA, agreement, trader, and sales declarations are owner-side gates. |
| Repository release policy prevents overlapping binary submissions. | `scripts/jetbrains_marketplace_status.py --require-upload-slot` blocks the protected workflow if a binary update is pending. | August 31 API check: 0.8.20 approved/listed, upload slot open; listing metadata pending. Recheck at dispatch. |

Official guidelines version 1.3 (effective March 31, 2026) were checked on
August 31. Name, English description, relevant change notes, 40px SVG icons,
source/vendor links, licenses, local permissions, and compatibility checks are
covered by the descriptor, archive preflight, and native tests. Account-side
agreements and trader declarations cannot be proven by source tests. Existing
0.8.20 approval is evidence of a prior review, not approval of this candidate.

## Required submission receipt

Before dispatching `jetbrains-v0.8.21`, retain all of the following:

1. `./gradlew.bat check guardianReleaseGate` passes on the tagged commit;
2. the protected workflow seals tag, commit, channel, ZIP SHA-256, and size;
3. `python scripts/jetbrains_marketplace_status.py --plugin-id 33009 --require-upload-slot --json` reports an available slot;
4. the Marketplace owner verifies account-side agreement, EULA, vendor/trader, and any applicable sales information; and
5. the authenticated Marketplace read-back shows the accepted upload.

The local gate can minimize avoidable hold-ups. JetBrains retains manual review
authority and the approval decision.
