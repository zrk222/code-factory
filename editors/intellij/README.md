# FactoryLine for JetBrains IDEs

Your change is ready for a closer look. Open the current diff or active file,
follow the local findings and evidence, and choose your next repair. Keep an
agent handoff inside one selected Change List, then bring it back for review
before deciding what to apply. FactoryLine keeps that decision with you.

Catch AI-generated tests that could never fail — before review. FactoryLine keeps local review evidence beside your code: see what changed, which evidence is available, what remains unproven, and the next review step.

## Review the change in front of you

1. Open **Tools > FactoryLine > Run First Proof** and confirm the workspace. This is a local setup demonstration, not a repository assessment.
2. To assess the repository, run `factory scan --root .` from the project.
3. In **Proof Review**, choose **Review Current Diff** or **Review This File**. Inspect structured findings, changed paths, unproven claims, and the suggested next action. Open a changed file, copy a handoff brief, or save a local JSON, Markdown, and Mermaid review packet.

A readable receipt is not automatically trusted: it remains unassessed until a verification path checks it. Missing, stale, unavailable, or unbound evidence stays incomplete. Proof Review analyzes local evidence; it does not run tests or decide whether a release is ready.

## Keep an AI repair inside scope

In **Repair Sandbox**, select one native Change List to create a hash-bound Scope Passport. Copy its sealed **AI Agent Proof Mission** into Junie or another coding agent yourself, then bring the returned Change List back for review. Candidate patch paths can be checked against the sealed scope. Independent verification and the human decision to apply remain separate steps.

Junie is supported, not required. FactoryLine provides a local guide and an optional project pack; it does not start or message Junie, read its chat, or treat an agent's completion claim as approval. Installing the pack is an explicit, conflict-safe project-file action.

Use FactoryLine when you want to turn an outcome into a buildable starting point or review AI and teammate changes with evidence. Open **Graph Ops** for the local evidence path, use **PRD Grill** with `factory prd grill PRD.md --root . --mode quick` to clarify requirements, and inspect **Proof Debt** in Plan-to-Proof Review. Star Code Factory on GitHub if the workflow helps.

## Local evidence, human release decisions

The adapter invokes the configured local `factory` executable after workspace confirmation. It does not upload project source or receipts, sign artifacts, or approve, publish, or deploy a release. Use your coding agent and analyzer as usual; FactoryLine displays the local evidence returned by its supported review commands.

## Install

1. Install the Code Factory CLI in the Python environment your JetBrains IDE uses.
2. Install **FactoryLine AI Proof** from the [JetBrains Marketplace](https://plugins.jetbrains.com/plugin/33009-factoryline) and restart the IDE.
3. Open the **FactoryLine** tool window or **Tools > FactoryLine**. If `factory` is not discoverable, set its absolute executable path under **Settings > Tools > FactoryLine**.
4. Use **Run First Proof** to check local setup; run `factory scan --root .` when you want a repository assessment.

For an offline installation, use a verified plugin ZIP from a matching FactoryLine release and choose **Install Plugin from Disk...**.

## Local development

Run the plugin's scoped release gate:

```powershell
.\gradlew.bat guardianReleaseGate
```

The ZIP is written to `build/distributions/`. `runIde` opens a sandboxed IDE for manual inspection.

## Platform and guides

The plugin targets the IntelliJ Platform 2025.2 baseline and is verified for IntelliJ IDEA, PyCharm, WebStorm, Rider, CLion, GoLand, RustRover, and DataGrip.

- [Junie workflow](../../docs/JUNIE_FACTORYLINE.md)
- [Verified Repair Sandbox](../../docs/REPAIR_SANDBOX.md)
- [GitHub Proof Review](../../docs/GITHUB_PROOF_REVIEW.md)
- [Marketplace release process](../../docs/JETBRAINS_MARKETPLACE.md)
