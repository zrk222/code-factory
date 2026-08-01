# Release Channels

Code Factory v0.23.1 publishes one verified source state through channel-specific
adapters. A successful GitHub release is not evidence that every moderated
listing has accepted the artifact.

| Channel | Artifact or surface | Release path | Success evidence |
| --- | --- | --- | --- |
| GitHub | Source tag, wheel, sdist, VSIX, JetBrains ZIP, media | Publish `v0.23.1`; `publish.yml` attaches the verified bundle | Public release URL and green workflow |
| PyPI | `factoryline-code-factory==0.23.1` | Trusted Publishing from `publish.yml` | PyPI project version and attestation |
| Hugging Face | Static Code Factory Space | Push `deploy/huggingface/` to `main` | Green Space workflow and public Space |
| Zenodo | Versioned source archive under concept DOI | GitHub release integration | Public version record; concept DOI remains stable |
| VS Code | `factoryline-vscode-0.7.0.vsix` | GitHub release bundle; Marketplace requires a separately configured publisher token | Installable VSIX or public Marketplace version |
| JetBrains | `factoryline-intellij-0.7.1.zip` | Scoped workflow update to public plugin 33009 | Public plugin/version page after moderation |
| Product Hunt | Product page, gallery, and YouTube link | Signed-in maker editor | Public page visibly reflects the new copy/media |

The release pipeline never treats a queued review, draft listing, uploaded
artifact, or workflow dispatch as a completed publication. Each channel is
reported as published, pending review, blocked, or not configured.
