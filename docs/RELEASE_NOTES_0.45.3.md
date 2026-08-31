# Code Factory 0.45.3 — independent proof for agents, analyzers, and App Review

Use your preferred coding agent and analyzer—FactoryLine independently decides
whether their green result deserves trust.

For a JetBrains Change List, the Proof Handshake now binds a sealed local scope,
human-confirmed intent, a supplied Qodana or SonarQube SARIF 2.1.0 report, and
optional non-hollow E2E evidence. A scope escape, a new analyzer finding beyond
the declared threshold, a hollow E2E receipt, an unrecognized report source,
or missing evidence remains visible. FactoryLine does not start an agent or
analyzer, read a chat, upload source, or approve a change.

Junie receives a project-scoped MCP entry only after typed confirmation.
GitHub Copilot receives a generated workspace proof-agent profile with the
same sealed mission and no-overwrite rule. Both integrations stay local and
supervised.

AppForge is now an IDE-native Mission Control tab. Before a team commits its
selected iOS build to another review queue, it can inspect the local evidence
story: user design input, storyboard, real iPhone/iPad media, App Review gate,
strict quality audit, SaaS journey, and submission dossier. That can prevent
avoidable rework and days-long repeat waiting cycles; AppForge cannot upload,
submit, or guarantee Apple approval.
