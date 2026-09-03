# FactoryLine 0.9.0 — Marketplace compliance evidence map

| Requirement or review risk | 0.9.0 evidence | Status and boundary |
| --- | --- | --- |
| Identity and version | `plugin.xml` id `app.factoryline`; Gradle version `0.9.0`; matching VS Code package version. | Local metadata check required before submission. |
| User-facing description | `plugin.xml`, README, and changelog describe Agent Proof Bridge and no-authority limits. | Locally reviewable; Marketplace listing review remains external. |
| Data and permissions | Handoff bridge rejects raw prompts, source bodies, URLs, credentials, and provider tokens; plugin provides local views. | No external identity/provider verification claimed. |
| Functionality safety | Read-only Graph Ops, MCP, and worklog projection; independent local tests cover stale contracts and invalid evidence. | A successful test suite does not guarantee Marketplace approval. |
| Release process | Build/package, Plugin Verifier, signing, and live binary-slot checks remain protected workflow gates. | JetBrains moderation timing and outcome are external. |
