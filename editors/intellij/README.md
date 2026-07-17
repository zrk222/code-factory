# FactoryLine for JetBrains IDEs

FactoryLine for JetBrains IDEs keeps the local proof loop next to the project. It
runs an explicit FactoryLine command, then displays the command result and the
newest local JSON receipt in a tool window.

## What It Does

- `FactoryLine: Run Spec-to-Ship Assembly` runs `factory assemble <feature> --root <project>`.
- `FactoryLine: Verify Feature Receipts` runs `factory verify <feature> --root <project>`.
- `FactoryLine: Open Local Meter` runs `factory meter --root <project> --json` after workspace confirmation.
- `FactoryLine: Analyze Changed Proof` runs `factory risk-diff --root <project> --json`.
- `FactoryLine: Open Latest Receipt` shows the newest JSON receipt below `.factory/` or `receipts/`.
- `FactoryLine: Check Latest Receipt Signature State` runs `factory receipt status` on that receipt. It reports signature presence or `UNSIGNED`; it does not claim signer identity.
- `FactoryLine: Open Local Factory Studio` opens the confirmed loopback target compiler.
- `FactoryLine: Open Product Missions` opens Studio in deterministic PRD-to-mission mode.
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

1. Install `factoryline-code-factory==0.17.1` into the Python environment that
   IntelliJ inherits.
2. Download `factoryline-intellij-0.3.0.zip` from the matching GitHub release.
3. In your JetBrains IDE, open **Settings > Plugins > gear menu > Install Plugin from Disk...** and select the ZIP.
4. Restart the IDE, then use the **Tools > FactoryLine** menu or the **FactoryLine** tool window.

Set an absolute executable path under **Settings > Tools > FactoryLine** only
when `factory` is not already discoverable on IntelliJ's PATH.
Product Missions create only supervised, approval-required local packets and do
not grant execute, merge, deploy, publish, connector, credential, or messaging authority.
The gutter navigator reads bounded local evidence only and never executes a
mission or changes an approval.

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

`marketplacePreflight` inspects the actual ZIP and fails when its descriptor,
light/dark plugin logos, vendor contact, project URL, or release notes are
missing. GitHub releases remain the current installation channel. The initial
Marketplace upload requires a human Vendor profile and review; after that
bootstrap, the scoped GitHub workflow publishes verified updates using a
Marketplace publisher token. See [the Marketplace runbook](../../docs/JETBRAINS_MARKETPLACE.md).
