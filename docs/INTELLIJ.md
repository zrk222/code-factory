# FactoryLine for JetBrains IDEs

FactoryLine for JetBrains IDEs brings the local proof loop into the IDE without
turning it into a hidden agent. Start with **Run First Proof**, which executes
`factory doctor --json` only after workspace confirmation and shows the redacted
local result. The remaining explicit actions are:

1. Run Spec-to-Ship Assembly.
2. Continue Assembly to Next Boundary.
3. Verify Feature Receipts.
4. Open Latest Receipt.
5. Analyze Changed Proof.
6. Check Latest Receipt Signature State.
7. Open Local Meter and Paired Savings Report.
8. Open Local Factory Studio.
9. Open Product Missions.
10. Open Unified Graph Ops.
11. Mission Graph & Provider Operations.

`REQ-*`, `FR-*`, and `NFR-*` text also receives a read-only FactoryLine gutter
marker. Selecting it opens the first deterministic local proof match under
`.factory`, `receipts`, `coverage`, `tests`, or `specs`; it runs no command and
changes no approval.

Feature-scoped commands require a feature name. Every command-executing action
requires an explicit local-workspace confirmation and is executed directly rather
than through a shell. The **FactoryLine** tool window shows the captured command
output and local JSON receipt content.

**Analyze Changed Proof** is backed by `factory risk-diff`; **Check Latest
Receipt Signature State** is backed by `factory receipt status`. A signature
state is not a signature-identity claim:
the plugin labels receipts unassessed until an explicit verification path proves
the expected signer identity.

**Open Local Meter** runs `factory meter --root <project> --json` only after the
same workspace confirmation. The tool window distinguishes measured wall time
from token values that a module has not reported.

**Open Local Factory Studio** starts `factory studio --root <project> --port 0
--no-browser` after an explicit confirmation. It opens the outcome-first
**Instant MVP** path by default; the Professional workflow tab retains Graph
Ops, Product Missions, proof reuse, policy, and enterprise controls. The plugin
accepts only a literal `127.0.0.1` URL and terminates the child process when the
project closes.

**Open Product Missions** uses the same confirmation, process lifecycle, and
literal-loopback checks, then opens Studio at `?mode=product`. Compiled missions
remain supervised and require separate execution and promotion approvals.

**Open Unified Graph Ops** uses the same loopback boundary and opens
`/graph-ops`. It visualizes the currently readable local Product, mission,
completion, proof, gate, trace, receipt, and artifact links; its one suggested
next action is fact-derived and it runs no validation or release operation.

**Mission Graph & Provider Operations** exposes initialization, status,
history, verification, Mermaid export, guarded event recording, and provider
routing. Every path must resolve inside the current workspace. BYOK input is an
environment-variable name from a verified policy; the plugin has no raw-key
field and redacts common credential shapes from captured output.

The same shared-platform gutter implementation is packaged for IntelliJ IDEA,
PyCharm, WebStorm, Rider, CLion, GoLand, RustRover, and DataGrip. Searches skip
dependency/build trees, ignore files larger than 2 MB, and stop after 2,000
candidate files.

## Install

1. Install FactoryLine:

   ```powershell
   pip install factoryline-code-factory==0.24.0
   ```

2. In your JetBrains IDE, open **Settings > Plugins > Marketplace**, search for
   **FactoryLine AI Proof**, and install the
   [official listing](https://plugins.jetbrains.com/plugin/33009-factoryline).
3. Restart the IDE, then open **Tools > FactoryLine > Run First Proof**.

For an offline installation, download a verified plugin ZIP from a FactoryLine
release and use **Settings > Plugins > gear menu > Install Plugin from Disk...**.

The default command is `factory` (`factory.exe` on Windows). Configure an
absolute path under **Settings > Tools > FactoryLine** when IntelliJ does not
inherit the Python Scripts directory on its `PATH`.

## Safety And Scope

The adapter has no network client, never uploads source or receipts, and does
not claim a pass or release decision on its own. The FactoryLine CLI remains
the decision maker and writes the receipts the plugin displays.

The adapter depends only on the shared IntelliJ Platform module. CI verifies
the packaged ZIP against IntelliJ IDEA, PyCharm, WebStorm, Rider, CLion,
GoLand, RustRover, and DataGrip from the 2025.2 baseline forward. It verifies
current stable builds, including an explicit DataGrip archive because archived
2025.2 installers are not available through the verifier resolver.

The packaged ZIP now has a deterministic Marketplace preflight: public project
and vendor metadata, light/dark 40px logos, release notes, and the packaged
artifact structure must all be present. GitHub releases remain the current
installation channel. JetBrains Marketplace initial upload is a one-time human
Vendor-profile action; subsequent verified updates are published by the scoped
GitHub workflow. See the
[Marketplace Acquisition Kit](JETBRAINS_MARKETPLACE_ACQUISITION_KIT.md) for the
two-minute start and IDE-native capture brief, and
[JetBrains Marketplace Release](JETBRAINS_MARKETPLACE.md) for the protected
publication gate.
