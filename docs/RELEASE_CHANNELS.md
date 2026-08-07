# Release Channels

Code Factory v0.26.0 publishes one verified source state through channel-specific
adapters. A successful GitHub release is not evidence that every moderated
listing has accepted the artifact.

| Channel | Artifact or surface | Release path | Success evidence |
| --- | --- | --- | --- |
| GitHub | Source tag, wheel, sdist, VSIX, JetBrains ZIP, media | Publish `v0.26.0`; `publish.yml` attaches the verified bundle | Public release URL and green workflow |
| PyPI | `factoryline-code-factory==0.26.0` | Trusted Publishing from `publish.yml` | PyPI project version and attestation |
| Hugging Face | Static Code Factory Space | Push `deploy/huggingface/` to `main` | Green Space workflow and public Space |
| Zenodo | Versioned source archive under concept DOI | GitHub release integration | Public version record; concept DOI remains stable |
| VS Code | `factoryline-vscode-0.8.1.vsix` | GitHub release bundle; Marketplace requires a separately configured publisher token | Installable VSIX or public Marketplace version |
| JetBrains | `factoryline-intellij-0.8.2.zip` | Scoped workflow update to public plugin 33009 | Installable ZIP or public plugin/version page after moderation |
| Product Hunt | Product page, gallery, and YouTube link | Signed-in maker editor | Public page visibly reflects the new copy/media |

The release pipeline never treats a queued review, draft listing, uploaded
artifact, or workflow dispatch as a completed publication. Each channel is
reported as published, pending review, blocked, or not configured.

JetBrains Marketplace publication remains blocked while the current submitted
update is pending Marketplace approval. Do not dispatch the 0.8.2 candidate
until the Marketplace status gate reports clear.

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
