# FactoryLine 0.8.18 — Marketplace compliance checklist

**Candidate state:** release candidate evidence only. This checklist reduces
avoidable review risk; it does not promise JetBrains approval or timing.

Official references: [Approval Guidelines](https://plugins.jetbrains.com/docs/marketplace/jetbrains-marketplace-approval-guidelines.html),
[upload guidance](https://plugins.jetbrains.com/docs/marketplace/uploading-a-new-plugin.html),
[listing guidance](https://plugins.jetbrains.com/docs/marketplace/best-practices-for-listing.html),
and [build-number rules](https://plugins.jetbrains.com/docs/intellij/build-number-ranges.html).

| Requirement / risk | Evidence in this candidate | Status boundary |
| --- | --- | --- |
| Distinct identity, factual English copy, and relevant release notes | `marketplacePreflight` checks `FactoryLine AI Proof`, vendor URL/email, version, change notes, and the two 40x40 SVG icons in the generated ZIP. | Local evidence; Marketplace originality and editorial review remain external. |
| Compatibility is verified, not merely declared | `since-build="252"` is open-ended, and `guardianReleaseGate` plus protected CI verify the sealed ZIP against the declared JetBrains matrix. | Local/current and CI evidence; JetBrains remains the final compatibility authority. |
| No covert data handling or privileged background repair | Guardian Core uses bounded in-memory aggregate observations; actions are confirmation-gated and read-only. No source upload, credentials, network client, or IDE mutation is shipped. | Source and tests are locally inspectable; Marketplace may independently assess runtime behavior. |
| Archive integrity and license context | Preflight checks safe archive paths, size, required notices, and prohibited credential/source-control-shaped entries. | Local package gate. |
| Legal, EULA, vendor/trader, and pricing state | MIT/Apache-2.0 notices are bundled; the active descriptor says the proof core is free and contains no checkout or entitlement logic. | Vendor-console declarations and future paid onboarding are owner-only external gates. |
| Pending binary updates are not bypassed | `scripts/jetbrains_marketplace_status.py --require-upload-slot --json` requires an open upload slot; the workflow seals tag, commit, channel, SHA-256, and size before publication. | Current read-only check: upload slot clear; metadata review is still pending. |

## Required release receipt

Retain the successful `./gradlew guardianReleaseGate` output, the sealed
`jetbrains-v0.8.18` tag/commit/SHA manifest, the protected compatibility matrix,
the Marketplace workflow URL, and authenticated Marketplace read-back after
upload and after approval. A green workflow is not a public approval receipt.
