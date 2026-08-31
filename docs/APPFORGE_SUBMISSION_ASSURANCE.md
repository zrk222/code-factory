# AppForge iOS Submission Assurance

## What it does

AppForge Submission Assurance is a local, fail-closed release dossier. It only
creates the final Markdown checklist and PDF when the same bundle identifier,
version, build number, and source commit have passed all four evidence lanes:

1. App Review readiness: required and conditionally applicable review risks.
2. Store media truth: authentic, hash-bound screenshots with accepted
   dimensions, count, route, journey, device-source, and named representation
   confirmation.
3. SaaS promise proof: OAuth/OIDC, checkout, webhook, entitlement, access, and
   revocation observations bound to the same release candidate.
4. Strict quality audit: confirmed user design input, visual/UX review,
   accessibility common-task matrix, and full-stack operational artifacts.

It is an evidence gate, not a submission bot. It does not upload a binary,
contact App Store Connect, create TestFlight testers, submit an app, or claim
Apple approval.

## Commands

```bash
factory revenue store-media-gate \
  --root . \
  --contract appforge/store-media-contract.json \
  --evidence appforge/store-media-evidence.json \
  --out .factory/appforge/store-media.json \
  --json

factory revenue quality-audit \
  --root . \
  --contract appforge/quality-contract.json \
  --evidence appforge/quality-evidence.json \
  --out .factory/appforge/quality-audit.json \
  --json

factory revenue submission-assurance \
  --root . \
  --contract appforge/submission-assurance-contract.json \
  --app-review .factory/appforge/app-review.json \
  --store-media .factory/appforge/store-media.json \
  --saas-proof .factory/saas-proof/latest.json \
  --quality-audit .factory/appforge/quality-audit.json \
  --out .factory/appforge/submission-assurance.json \
  --report-dir .factory/appforge/reports \
  --json
```

The last command writes a sealed JSON receipt in either state. It writes the
human-readable `.md` and `.pdf` only with
`APPFORGE_SUBMISSION_DOSSIER_READY`.

## Strict design and full-stack checks

The quality contract requires hash-bound artifacts for every listed check. A
plain checkbox is rejected. Each artifact must stay inside the workspace, match
its declared SHA-256, be dated, and identify who performed it.

| Area | Required checks |
| --- | --- |
| Experience design | device-specific layout, visual hierarchy, typography/readability, semantic color/contrast, loading-empty-error states, touch targets/gesture alternatives, Dark Mode/Dynamic Type, reduced motion/feedback, iPad adaptive layout |
| Accessibility | a common-task matrix covering the supported device types; use it before making any App Store accessibility declaration |
| Build and runtime | signed archive/clean build, unit/integration tests, UI automation, physical-device smoke, backend review environment, authentication/authorization, network failure recovery, privacy SDK/processor inventory, performance budget, observability/rollback, dependency and secret scan |
| Conditional commerce | purchase and restore must be marked required or not applicable by a named reviewer with a concrete rationale |

The evidence also requires a named design reviewer to affirm that supplied user
design input was considered and binds a storyboard digest. This prevents a
beautiful-but-generic result from being marked ready without the user’s stated
design direction in the chain of evidence.

## iOS Store sources and boundaries

The gates operationalize local evidence against current Apple guidance, but
they cannot certify compliance or promise an App Review result. Apple’s
guidelines change and Apple alone decides review outcomes.

- [App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/)
- [Screenshot specifications](https://developer.apple.com/help/app-store-connect/reference/app-information/screenshot-specifications)
- [Screenshot and app-preview upload rules](https://developer.apple.com/help/app-store-connect/manage-app-information/upload-app-previews-and-screenshots)
- [Accessibility Nutrition Labels](https://developer.apple.com/help/app-store-connect/manage-app-accessibility/overview-of-accessibility-nutrition-labels/)

For an iPad-capable app, current Apple guidance requires 13-inch iPad media.
Apple allows one to ten screenshots per device set in JPEG, JPG, or PNG. The
project’s `10 iPhone + 3 iPad` standard is intentionally stricter than Apple’s
minimum; it is a product-quality policy, not an Apple minimum.

## Example quality contract

```json
{
  "schema": "factory.appforge.quality-audit-contract.v1",
  "candidate": {
    "bundle_identifier": "com.example.app",
    "version": "1.0.0",
    "build_number": "100",
    "source_commit": "40-character-commit-sha"
  },
  "user_design_input_sha256": "sha256-of-confirmed-user-design-input",
  "conditional": {
    "purchase_and_restore": {
      "status": "required",
      "reviewed_by": "Release owner",
      "rationale": "The candidate sells a restorable subscription in the app."
    }
  }
}
```

Do not place credentials, review logins, personal data, raw test logs, or
unredacted screenshots in these JSON receipts. Store those separately under an
access-controlled release process and include only content hashes here.
