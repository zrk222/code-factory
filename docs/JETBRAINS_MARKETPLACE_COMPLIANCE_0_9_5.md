# FactoryLine 0.9.5 — Marketplace compliance evidence map

| Requirement or review risk | 0.9.5 evidence | Status and boundary |
| --- | --- | --- |
| Identity and version | `editors/intellij/build.gradle.kts` declares `0.9.5`; the stable plugin id remains `app.factoryline`. | Local metadata is aligned; a Marketplace listing read-back remains required. |
| Junie compatibility | `factory junie manifest` describes `.junie/AGENTS.md`, `.junie/mcp/mcp.json`, and the optional `.junie/agents/factoryline-proof.md` subagent with per-file SHA-256 digests. | The pack is project-scoped and opt-in; Junie remains optional and externally enabled. |
| Read-only subagent boundary | The native Junie frontmatter allowlists only `Read`, `Grep`, `Glob`, and `code-factory`, with `permissionMode: plan` and a 12-turn cap. | The subagent cannot edit files, execute shell commands, browse the web, ask for scope changes, or approve work. Feature availability depends on the installed Junie build. |
| Conflict-safe installation | `factory junie install --confirmation "INSTALL Junie FactoryLine Pack"` checks all targets before writing and refuses differing team-owned files. | Installation is explicit and local; it does not enable Junie, contact JetBrains, or mutate provider state. |
| Independent evidence | The taxonomy and contribution card retain exact tool vocabulary, changed-file rationale, local hashes, unknowns, and a visible credit line. | A declaration is not Junie telemetry, proof of private calls, test execution, or approval. |
| Release controls | Gradle `test verifyPlugin` validates the packaged archive against IU-252.28539.54. | Upload, processing, moderation, and Marketplace approval remain external JetBrains states. |

This checklist records local evidence and boundaries. It does not promise
Marketplace acceptance or approval.
