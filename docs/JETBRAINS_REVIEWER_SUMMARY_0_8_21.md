# FactoryLine 0.8.21 — JetBrains reviewer summary

FactoryLine is a local, supervised evidence layer for JetBrains projects. It
does not replace Junie, GitHub Copilot, Qodana, SonarQube, App Store Connect,
or human review.

| Reviewer or developer concern | Shipped response | Evidence and boundary |
| --- | --- | --- |
| A coding agent and analyzer both say green, but the change escaped scope or its tests can no longer reject the intended failure. | **Proof Handshake** binds a sealed Change List, human-confirmed intent, supplied Qodana/SonarQube SARIF, and optional E2E receipt. Scope escape, unfamiliar/ambiguous SARIF, analyzer regression, hollow E2E, and missing evidence stay explicit. | `factoryline/analysis_evidence.py`, `factoryline/jetbrains_handshake.py`, `tests/test_analysis_evidence.py`, `tests/test_jetbrains_handshake.py`. It never starts an agent/analyzer or approves a change. |
| A team wants an MCP path without a secret or overwrite surprise. | **Junie MCP** and **Copilot proof agent** configuration is project-scoped, typed-confirmation gated, idempotent, and refuses conflicting existing files. | `factoryline/mcp_setup.py`, `tests/test_mcp_setup.py`. The client retains MCP approval and agent execution authority. |
| An iOS team only discovers missing Apple-review evidence after entering another queue. | **AppForge Mission Control** reads candidate-bound local receipt status for mission/design input, storyboard, App Review gate, strict quality audit, and submission dossier; it opens local Graph Ops for the full evidence chain. | `FactoryLineAppForge.kt`, `FactoryLineCore.kt`, `FactoryLineActions.kt`, `FactoryLineCoreTest`. It can surface preventable rework; it cannot access credentials, upload, start TestFlight, submit, or guarantee approval. |
| A plugin needs a repeatable, artifact-level release gate. | `guardianReleaseGate` runs tests, packages the ZIP, runs Plugin Verifier, and checks descriptor/icons/licenses/contact/archives from the generated artifact. | `editors/intellij/build.gradle.kts`; reports are retained below `build/reports/`. |

**Fast local path:** open **View | Tool Windows | FactoryLine | AppForge**, choose
**Refresh local AppForge status**, then inspect the bounded result. No Apple,
provider, or MCP account is needed. The plugin remains local and human-led.
