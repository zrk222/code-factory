# FactoryLine for JetBrains IDEs

FactoryLine for JetBrains IDEs keeps the local proof loop next to the project. It
runs an explicit FactoryLine command, then displays the command result and the
newest local JSON receipt in a tool window.

**Why pay for opaque app generators?** Create a reviewable MVP starting state
in minutes, inspect the proof path in the IDE, and extend it when you are ready.
Start with **Tools > FactoryLine > Run First Proof**, then run
`factory mvp "Build an approval tracker" --root .` and open **Graph Ops**. A
starter remains a starting state until product-specific proof exists.

## What It Does

- `FactoryLine: Run Spec-to-Ship Assembly` runs `factory assemble <feature> --root <project>`.
- `FactoryLine: Continue Assembly to Next Boundary` resumes safe local stages
  with `factory continue <feature> --root <project>`.
- `FactoryLine: Verify Feature Receipts` runs `factory verify <feature> --root <project>`.
- `FactoryLine: Open Local Meter` runs `factory meter --root <project> --json` after workspace confirmation.
- `FactoryLine: Analyze Changed Proof` runs `factory risk-diff --root <project> --json`.
- `FactoryLine: Open Latest Receipt` shows the newest JSON receipt below `.factory/` or `receipts/`.
- `FactoryLine: Check Latest Receipt Signature State` runs `factory receipt status` on that receipt. It reports signature presence or `UNSIGNED`; it does not claim signer identity.
- `FactoryLine: Open Local Factory Studio` opens the confirmed loopback target compiler.
- `FactoryLine: Open Product Missions` opens Studio in deterministic PRD-to-mission mode.
- `FactoryLine: Open Unified Graph Ops` opens the bounded, read-only local evidence map.
- **PRD Grill (terminal workflow)** runs `factory prd grill PRD.md --root <project>`
  to write a capped, source-bound clarification sheet before PRD optimization
  or compilation. It never modifies the PRD or authorizes implementation.
- `FactoryLine: Mission Graph & Provider Operations` initializes and inspects
  durable graphs, verifies receipt chains, exports Mermaid, records guarded
  events, and routes a JetBrains-selected secret-free BYOK policy.
- `REQ-*`, `FR-*`, and `NFR-*` references receive a read-only gutter link to
  matching local proof under `.factory`, `receipts`, `coverage`, `tests`, or `specs`.

## Safety Boundary

The adapter runs a command only after a feature-name prompt and explicit local-workspace confirmation.
It invokes the configured executable directly through IntelliJ's process API:
it does not start a shell, construct command strings, upload source code, send
receipts over the network, or certify a release by itself.

The receipt viewer is deliberately fail-closed: a readable receipt is marked
**unassessed** until an explicit verification path establishes the claim. The
adapter never silently signs a receipt, applies an override, or converts an
untrusted/missing receipt into a green state.

## Install

1. Install `factoryline-code-factory==0.25.0` into the Python environment that
   IntelliJ inherits.
2. In your JetBrains IDE, open **Settings > Plugins > Marketplace**, search for
   **FactoryLine**, and install the
   [official listing](https://plugins.jetbrains.com/plugin/33009-factoryline).
3. Restart the IDE, then use the **Tools > FactoryLine** menu or the
   **FactoryLine** tool window.

For an offline installation, download a verified plugin ZIP from a matching
FactoryLine release and use **Install Plugin from Disk...**.

Set an absolute executable path under **Settings > Tools > FactoryLine** only
when `factory` is not already discoverable on IntelliJ's PATH.
Product Missions create only supervised, approval-required local packets and do
not grant execute, merge, deploy, publish, connector, credential, or messaging authority.
The gutter navigator reads bounded local evidence only and never executes a
mission or changes an approval.

After a successful local proof or assembly command, FactoryLine may offer an
optional **Star Code Factory** action once per installed plugin version. It only
opens the repository when you select it and shares no workspace data.

## Local Development

```powershell
.\gradlew.bat check buildPlugin verifyPlugin
```

The output ZIP is written to `build/distributions/`. `runIde` opens a sandboxed
IntelliJ instance for manual inspection.

## Scope

This is a JetBrains Platform plugin, with only the shared
`com.intellij.modules.platform` dependency. CI verifies its ZIP against
IntelliJ IDEA, PyCharm, WebStorm, Rider, CLion, GoLand, RustRover, and
DataGrip builds from the 2025.2 baseline forward. The CI matrix verifies
current stable builds, including an explicit DataGrip archive because archived
2025.2 installers are not available through the verifier resolver.

Code Factory 0.20 also includes an optional hosted GitHub PR-assurance adapter,
a durable mission graph, and a secret-free multi-provider route selector.
It is deployed separately from this local IDE plugin; see
[Hosted PR assurance](../../docs/HOSTED_PR_ASSURANCE.md).

`marketplacePreflight` inspects the actual ZIP and fails when its descriptor,
light/dark plugin logos, vendor contact, project URL, or release notes are
missing. GitHub releases remain the current installation channel. The initial
Marketplace upload requires a human Vendor profile and review; after that
bootstrap, the scoped GitHub workflow publishes verified updates using a
Marketplace publisher token. See [the Marketplace runbook](../../docs/JETBRAINS_MARKETPLACE.md).

### Contradiction gate (0.25.0)

`factory cdte scan` detects architecturally incompatible NFR pairs before any
code is generated, by deterministic lookup over a decision table. No model is
called. Analysis is tiered `measured` / `modeled` / `structural`, and a modeled
analysis whose inputs are absent is withheld rather than estimated. Critical and
high severity conflicts engage the fail-closed boundary and pause the line at
`nfr_conflict`.
