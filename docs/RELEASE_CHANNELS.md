# Release Channels

Code Factory v0.28.2 publishes one verified source state through channel-specific
adapters. A successful GitHub release is not evidence that every moderated
listing has accepted the artifact.

| Channel | Artifact or surface | Release path | Success evidence |
| --- | --- | --- | --- |
| GitHub | Source tag, wheel, sdist, VSIX, JetBrains ZIP, media | Publish `v0.28.2`; `publish.yml` attaches the verified bundle | Public release URL and green workflow |
| PyPI | `factoryline-code-factory==0.28.2` | Trusted Publishing from `publish.yml` | PyPI project version and attestation |
| Hugging Face | Static Code Factory Space | Push `deploy/huggingface/` to `main` | Green Space workflow and public Space |
| Zenodo | Versioned source archive under concept DOI | GitHub release integration | Public version record; concept DOI remains stable |
| VS Code | `factoryline-vscode-0.8.4.vsix` | GitHub release bundle; protected `vscode-marketplace.yml` publishes an immutable, verified VSIX when its scoped publisher credential is configured | Installable VSIX or public Marketplace version |
| JetBrains | `factoryline-intellij-0.8.4.zip` | Scoped workflow update to public plugin 33009 | Installable ZIP or public plugin/version page after moderation |
| Product Hunt | Product page, gallery, and YouTube link | Signed-in maker editor | Public page visibly reflects the new copy/media |

The release pipeline never treats a queued review, draft listing, uploaded
artifact, or workflow dispatch as a completed publication. Each channel is
reported as published, pending review, blocked, or not configured.

JetBrains Marketplace publication remains blocked while the current submitted
update is pending Marketplace approval. Do not dispatch the 0.8.4 candidate
until the Marketplace status gate reports clear.

### Visual Studio Marketplace publisher setup

The package is already bound to publisher `zrk222` and extension name
`factoryline-vscode`. To enable the separately protected marketplace lane:

1. Sign in to the Visual Studio Marketplace publisher portal with the account
   that owns `zrk222`.
2. Create a publisher credential with only **Marketplace (Manage)** scope and
   a bounded expiry. Store it as the `VSCE_PAT` secret in the GitHub Actions
   environment named `vscode-marketplace`; never put it in source, a release
   asset, or a repository-level secret.
3. Create or protect the `vscode-marketplace` environment with the repository's
   normal release reviewers.
4. Dispatch **Publish VS Code Marketplace extension** for the immutable
   release tag, first with `publish=false`. After the green candidate receipt
   is reviewed, dispatch it again with `publish=true`.

The workflow verifies the tag-to-commit binding, restores from the lockfile,
runs the high-severity audit and tests, seals the VSIX SHA-256, and verifies
the sealed artifact again before it can call the Marketplace. `vsce` receives
the environment-scoped `VSCE_PAT` only in the protected publication job. A
missing credential fails closed at the publish boundary. Replace this PAT path
with the Marketplace's supported Microsoft Entra automation path before the
December 1, 2026 global PAT retirement.

### 0.28.2 Marketplace compatibility

The VS Code adapter changes only its Marketplace metadata: it is classified as
`Testing`, the accepted Marketplace category. The extension remains local-first
and does not change its runtime permissions or behavior.

### 0.28.0 product surfaces

Proof Review, Verified Repair Sandbox, and Workspace Load Advisor are available
in the JetBrains adapter. They produce bounded local review packets and never
edit code, invoke a model, access credentials, or certify runtime isolation.

### Verifier Plane (0.27.0)

The Verifier Plane is release-visible but not a release authority. Its receipts
prove supplied local byte bindings, declared independent identities, and
deterministic checks. Runtime isolation, egress policy, and credential handling
remain separately evidenced by an external supervised runner.

### Contradiction gate (0.26.0)

`factory cdte scan` detects architecturally incompatible NFR pairs before any
code is generated, by deterministic lookup over a decision table. No model is
called. Analysis is tiered `measured` / `modeled` / `structural`, and a modeled
analysis whose inputs are absent is withheld rather than estimated. Critical and
high severity conflicts engage the fail-closed boundary and pause the line at
`nfr_conflict`.

### Habituation gate (0.26.0)

`factory habituation status` calibrates the human approval signal against each
reviewer's own baseline and escalates: surface, second approver, fail closed.
Blocking is refused until blind-spot re-review outcomes correct the proxy.
Public exports carry distributions only, never per-reviewer rows.
