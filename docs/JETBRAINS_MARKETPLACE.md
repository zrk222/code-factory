# JetBrains Marketplace Release

## Current Distribution Status

FactoryLine for JetBrains is installable today from the matching GitHub release
ZIP. The ZIP is binary-verified across IntelliJ IDEA, PyCharm, WebStorm, Rider,
CLion, GoLand, RustRover, and DataGrip from the 2025.2 baseline forward.

JetBrains Marketplace is a separate moderated distribution channel. Do not say
the plugin is on Marketplace until its public Marketplace URL exists. The first
upload needs a human JetBrains account, Vendor profile, Developer Agreement,
license selection, and review. This is a platform-owned approval boundary, not
a missing FactoryLine gate.

## Artifact Gate

Run this before any upload:

```powershell
Set-Location editors/intellij
.\gradlew.bat check buildPlugin verifyPlugin marketplacePreflight
```

`marketplacePreflight` reads the generated ZIP, not just source files. It
requires the packaged main JAR to contain:

- `META-INF/plugin.xml` with the FactoryLine project and vendor contact URLs.
- `META-INF/pluginIcon.svg` and `META-INF/pluginIcon_dark.svg`.
- Marketplace-visible change notes.

It does not certify JetBrains review, Vendor identity, license selection, tags,
or a public listing. Those remain visible approval steps in Marketplace.

## One-Time Initial Upload

1. Sign in at <https://plugins.jetbrains.com> and choose **Upload plugin**.
2. Select or create the FactoryLine Vendor profile and accept the Developer
   Agreement when prompted.
3. Upload the release ZIP:
   <https://github.com/zrk222/code-factory/releases/download/v0.22.0/factoryline-intellij-0.7.0.zip>.
4. Set the license to the repository's `MIT OR Apache-2.0` terms and link
   the public source: <https://github.com/zrk222/code-factory>.
5. Choose only Marketplace tags that accurately describe local developer
   workflow and code-quality tooling. Add the public documentation URL and a
   concise getting-started instruction from [FactoryLine for JetBrains IDEs](INTELLIJ.md).
6. Submit the listing for JetBrains review. Save the resulting public plugin URL
   in this document and the root README only after it is visible.

The descriptor's first sentence is the Marketplace preview-card summary:
"Run local FactoryLine gates and inspect receipts without leaving your IDE."
It deliberately does not claim autonomous releases, source upload, signing, or
Marketplace approval.

## Automated Updates After Bootstrap

After JetBrains accepts the first upload:

1. Create a scoped `JETBRAINS_MARKETPLACE_TOKEN` secret in the GitHub
   `jetbrains-marketplace` environment. It must belong only to the FactoryLine
   Marketplace plugin.
2. Create a dedicated immutable tag matching the plugin version, such as
   `jetbrains-v0.7.1`, then run **Publish JetBrains Marketplace plugin** from
   GitHub Actions against that tag and the intended Marketplace channel.
3. The unprivileged validation job confirms the ref is a dedicated JetBrains version tag,
   runs Kotlin tests, builds the ZIP, performs binary verification, and runs
   `marketplacePreflight` without access to the publisher token.
4. Validation writes a secret-free manifest binding the ZIP to its SHA-256,
   size, plugin identity and version, release tag, commit, and channel. Both the
   ZIP and manifest are uploaded as one short-lived Actions artifact.
5. The protected publication job downloads that artifact, verifies every bound
   value, and passes the exact validated ZIP to `publishPlugin`. The scoped token
   is available only in this final job. Verifier and test reports are retained
   for failed as well as successful validation runs.
6. Confirm the new Marketplace version and public compatibility display before
   announcing it.

The workflow does not perform the first upload automatically. JetBrains requires
a human Vendor profile and initial listing choices before token-based updates can
be associated with a plugin.
