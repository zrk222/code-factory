# AppForge App Review Gate

## The review-queue story

You have one selected build and a review queue that may take days to come back
around. The avoidable failure is discovering after submission that the real
restore path was never exercised, the iPad path ends early, screenshots no
longer match the build, reviewer access is incomplete, or privacy and metadata
drifted from runtime behavior.

AppForge makes those candidate-bound evidence gaps visible before the human
chooses to enter the queue. It keeps the user’s design intent and storyboard in
the review story, then joins real iPhone/iPad media, strict quality evidence,
SaaS journey evidence, and the App Review worklist into one local dossier.
That can avoid preventable rework and days-long repeat review cycles; it does
not promise Apple approval or replace a human release decision.

It is available as a standalone local command and as an integrated Code Factory/AppForge receipt visible through Graph Ops, MCP, and WebMCP.

For a full local candidate dossier - including hash-bound Store media, strict
design/accessibility/full-stack evidence, SaaS lifecycle proof, and a final
Markdown/PDF checklist - use [AppForge Submission Assurance](APPFORGE_SUBMISSION_ASSURANCE.md).

```bash
factory revenue app-review-gate \
  --root . \
  --contract app-review-contract.json \
  --evidence app-review-evidence.json \
  --out .factory/appforge/release/app-review.json \
  --json
```

## Why it blocks

The gate checks 30 policy and release-risk classes against the exact bundle identifier, version, build number, and source commit. Universal rules always require evidence. Conditional rules—such as subscriptions, account creation, social login, user-generated content, children, health, finance, location, or AI-generated content—must be classified by a named reviewer as either required or not applicable with a concrete rationale. Omission is a failure.

The registry covers:

- app completeness, launch stability, reviewer notes, and reviewer access;
- accurate metadata, authentic screenshots, supported-device paths, and age rating;
- purchase, restore, Sandbox products, subscriptions, and pricing disclosures;
- privacy policy, runtime privacy attestation, permission minimization, security, and account deletion;
- accessibility tasks, minimum functionality, iPad navigation, and third-party rights;
- login services, UGC, children, health, finance, location, AI content, and export compliance.

## Evidence boundary

The gate is designed to minimize avoidable rejection risk and save rework/waiting time before submission. It does not guarantee approval, interpret law, upload a build, contact Apple, or submit an app. A “greater than 90% rejection reduction” is a product target, not a published result, until a representative measured cohort supports it.

Official sources are hashable inputs to the existing policy-drift workflow:

- [App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/)
- [App information](https://developer.apple.com/help/app-store-connect/reference/app-information/app-information)
- [Accessibility](https://developer.apple.com/design/human-interface-guidelines/accessibility)
- [Export compliance](https://developer.apple.com/help/app-store-connect/manage-app-information/overview-of-export-compliance)
