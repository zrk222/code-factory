# AppForge Release Rehearsal

## What it prevents

A passing local AppForge dossier is not an archive, an upload, provider
processing, TestFlight tester delivery, beta-review submission, App Review
submission, or an Apple decision. Release Rehearsal makes those boundaries
visible before a human operates a release tool.

It is a local, credential-free planning and validation step. It never reads a
Fastfile, invokes Fastlane or App Store Connect CLI, accesses a keychain or an
environment secret, signs an artifact, uploads a build, contacts Apple, or
submits a review.

## Why these two patterns

[fastlane](https://github.com/fastlane/fastlane) packages established local
automation around lanes, build artifacts, screenshots, signing, and release
work. AppForge adopts its useful *lane declaration* discipline, but does not
execute or vendor fastlane.

[App Store Connect CLI](https://github.com/rorkai/App-Store-Connect-CLI)
documents strict validation, dry-run release staging, explicit confirmation for
state-changing commands, and distinct release lifecycle states. AppForge adopts
that staged, read-back-first model, but does not invoke the CLI or claim any
provider state from a local file.

[Cider](https://github.com/cidertool/cider) uses an expressive YAML
configuration to update metadata and submit a previously uploaded build through
Apple APIs. AppForge adopts the useful declarative-manifest pattern by sealing a
credential-free YAML manifest path and hash beside the exact candidate. It does
not parse, execute, vendor, or submit through Cider (the upstream project is
GPL-3.0-or-later), and it treats Cider's later provider results as external
facts that require authenticated read-back.

[Swiftlane](https://github.com/onmyway133/Swiftlane) treats a type-safe Swift
script as the build workflow's source of truth and exposes explicit build,
test, archive, export, screenshot, and App Store Connect actions. AppForge
borrows its useful release-sequence discipline by hashing a Swift workflow and
requiring visible `Workflow`, `Build`, `Test`, `Archive`, and `ExportArchive`
source stages. That is a static source-presence check, not proof that Xcode,
Swiftlane, signing, or export actually ran.

[Zealot](https://github.com/tryzealot/zealot) is a self-hosted, multi-platform
beta-distribution system with app artifact inspection, channels, testers, SDKs,
and API integrations. AppForge borrows the useful artifact/channel/audience
separation as a provider-neutral JSON manifest. It never connects to a Zealot
server or treats the manifest as proof that a tester was assigned, invited, or
received a build.

## Inputs

Prepare three workspace-contained JSON files:

1. an exact AppForge release candidate;
2. a hash-valid, ready submission-assurance receipt for that same candidate;
3. one credential-free release automation profile.

No raw secret, token, password, API key, private key, credential reference, or
extra provider option is permitted in the profile. Secrets stay in the human
operator's authenticated environment and are never copied into Code Factory.

### Fastlane profile

```json
{
  "schema": "factory.appforge.release-automation-profile.v1",
  "candidate": {
    "bundle_identifier": "com.example.app",
    "version": "1.2.3",
    "build_number": "42",
    "source_commit": "<40 lowercase hex characters>"
  },
  "provider": "fastlane",
  "release_channel": "testflight_external",
  "provider_config": { "lane": "beta_release" }
}
```

### App Store Connect CLI profile

```json
{
  "schema": "factory.appforge.release-automation-profile.v1",
  "candidate": {
    "bundle_identifier": "com.example.app",
    "version": "1.2.3",
    "build_number": "42",
    "source_commit": "<40 lowercase hex characters>"
  },
  "provider": "asc_cli",
  "release_channel": "app_store",
  "provider_config": { "app_store_connect_app_id": "123456789" }
}
```

### Cider manifest profile

```json
{
  "schema": "factory.appforge.release-automation-profile.v1",
  "candidate": {
    "bundle_identifier": "com.example.app",
    "version": "1.2.3",
    "build_number": "42",
    "source_commit": "<40 lowercase hex characters>"
  },
  "provider": "cider",
  "release_channel": "app_store",
  "provider_config": { "manifest_path": "Cider.yml" }
}
```

The YAML file is kept local, must be UTF-8 and at most 1 MiB, and is stored as
a path plus SHA-256 only. Credential-like YAML keys are rejected. AppForge
does not interpret the manifest as proof that Cider will accept it or that
Apple will accept a submission.

### Swiftlane workflow profile

```json
{
  "schema": "factory.appforge.release-automation-profile.v1",
  "candidate": {
    "bundle_identifier": "com.example.app",
    "version": "1.2.3",
    "build_number": "42",
    "source_commit": "<40 lowercase hex characters>"
  },
  "provider": "swiftlane",
  "release_channel": "app_store",
  "provider_config": { "workflow_path": "Release.swift" }
}
```

The source file is local, UTF-8, at most 1 MiB, and hash-bound to the
rehearsal. AppForge requires visible `Workflow`, `Build`, `Test`, `Archive`,
and `ExportArchive` stages so an incomplete release script cannot be presented
as a complete local sequence. It never runs the script, Xcode, a keychain
operation, signing action, or upload.

### Zealot-style beta-distribution profile

```json
{
  "schema": "factory.appforge.release-automation-profile.v1",
  "candidate": {
    "bundle_identifier": "com.example.app",
    "version": "1.2.3",
    "build_number": "42",
    "source_commit": "<40 lowercase hex characters>"
  },
  "provider": "zealot",
  "release_channel": "beta_distribution",
  "provider_config": { "manifest_path": "beta-distribution.json" }
}
```

The referenced manifest is `factory.appforge.beta-distribution-manifest.v1`:

```json
{
  "schema": "factory.appforge.beta-distribution-manifest.v1",
  "candidate": { "bundle_identifier": "com.example.app", "version": "1.2.3", "build_number": "42", "source_commit": "<40 lowercase hex characters>" },
  "platform": "ios",
  "artifact": { "sha256": "<64 lowercase hex characters>" },
  "distribution": { "channel": "internal-qa", "audience_ref": "ios-qa" }
}
```

It seals the intended artifact, distribution channel, and audience reference,
not a delivered build. Actual group assignment, invitation, and recipient
delivery remain `not_attempted` until an authenticated provider read-back is
captured separately.

## Create the rehearsal

```powershell
factory revenue appforge-rehearse `
  --root . `
  --candidate .factory/appforge/candidate.json `
  --submission-assurance .factory/appforge/submission-assurance.json `
  --profile .factory/appforge/release-profile.json `
  --out .factory/appforge/release-rehearsal.json `
  --json
```

The output is SHA-256 sealed to the exact candidate, local assurance receipt,
and profile. It fails closed for path escape, oversized/malformed input,
candidate drift, a non-ready or tampered assurance receipt, secret-like keys,
unknown providers, invalid lane/app identifiers, unsupported provider fields,
or any matrix that wrongly reports an external state as ready.

## Fixed external-state matrix

| Stage | Rehearsal result |
| --- | --- |
| Local readiness | `ready` only after the exact local assurance receipt is valid |
| Archive/export | `not_attempted` |
| Upload | `not_attempted` |
| Provider processing | `not_attempted` |
| Tester group assignment | `not_attempted` or `not_applicable` |
| Tester invitation read-back | `not_attempted` or `not_applicable` |
| External beta review submission | `not_attempted` or `not_applicable` |
| App Review submission | `not_attempted` or `not_applicable` |
| App Review decision | `not_attempted` or `not_applicable` |

The channel determines the valid `not_applicable` states. `beta_distribution`
keeps beta group and invitation states open while App Review stages are not
applicable. A local rehearsal can never mark any external provider stage as
`ready`.

## Human handoff after rehearsal

1. Review the exact candidate and profile in the sealed receipt.
2. In the separately authenticated release environment, review the declared
   Fastlane lane or run the provider's own strict/dry-run validation flow.
3. If a human chooses to perform a provider action, read back upload,
   processing, tester group, invitation, beta review, App Review submission,
   and decision from App Store Connect as distinct facts.
4. Record external evidence through the existing supervised AppForge path.

This is deliberately not a shortcut around Apple controls or approval. It is a
way to avoid falsely reporting that an earlier release stage proves a later
one.

## Read-only visibility

Use `factory revenue appforge-status`, local MCP
`factory.appforge_release_rehearsal_status`, or the matching Graph Ops WebMCP
tool to inspect a sealed rehearsal. Those surfaces cannot create, modify, or
run a rehearsal or a provider action.
