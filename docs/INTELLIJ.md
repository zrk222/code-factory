# FactoryLine for JetBrains IDEs

FactoryLine for JetBrains IDEs brings the local proof loop into the IDE without
turning it into a hidden agent. It offers seven explicit actions:

1. Run Spec-to-Ship Assembly.
2. Verify Feature Receipts.
3. Open Latest Receipt.
4. Analyze Changed Proof.
5. Check Latest Receipt Signature State.
6. Open Local Meter.
7. Open Local Factory Studio.

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
--no-browser` after an explicit confirmation. The plugin accepts only a literal
`127.0.0.1` URL, opens it with the JetBrains browser API, and terminates the
child process when the project closes.

## Install

1. Install FactoryLine:

   ```powershell
   pip install factoryline-code-factory==0.14.0
   ```

2. Download `factoryline-intellij-0.2.0.zip` from the FactoryLine GitHub
   release that introduced this adapter.
3. In your JetBrains IDE: **Settings > Plugins > gear menu > Install Plugin from Disk...**.
4. Select the ZIP, restart, then open **Tools > FactoryLine**.

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
GitHub workflow. See [JetBrains Marketplace Release](JETBRAINS_MARKETPLACE.md).
