# FactoryLine for VS Code

Run a bounded FactoryLine command and inspect the local JSON receipt without
leaving VS Code. The extension never uploads your workspace, code, or receipts.

## Commands

- **FactoryLine: Run Spec-to-Ship Assembly** runs `factory assemble <feature> --root <workspace>`.
- **FactoryLine: Verify Feature Receipts** runs `factory verify <feature> --root <workspace>`.
- **FactoryLine: Open Local Meter** reads `factory meter --root <workspace> --json` after workspace confirmation.
- **FactoryLine: Open Latest Receipt** finds JSON under `.factory/` and `receipts/`, then renders a local receipt panel.
- **FactoryLine: Open Local Factory Studio** opens the confirmed loopback target compiler.
- **FactoryLine: Open Product Missions** opens Studio in deterministic PRD-to-mission mode.
- Requirement IDs such as `REQ-*`, `FR-*`, and `NFR-*` receive a read-only
  CodeLens that opens matching local proof in `.factory`, `receipts`,
  `coverage`, `tests`, or `specs`.

Each command requires a trusted VS Code workspace. FactoryLine accepts only a
feature name containing letters, digits, hyphens, and underscores; it does not
pass arbitrary shell fragments to your terminal.

## Install

Install the Code Factory CLI first:

```powershell
pip install factoryline-code-factory==0.17.1
```

Build a local VSIX from this directory, then install it in VS Code:

```powershell
npm ci
npm run package
code --install-extension factoryline-vscode-0.3.0.vsix
```

Set `factoryline.command` if the `factory` executable is not on VS Code's PATH.
Product Missions create only supervised, approval-required local packets and do
not grant execute, merge, deploy, publish, connector, credential, or messaging authority.
Requirement CodeLens navigation reads bounded local text artifacts only; it does
not run FactoryLine or change approval state.

## Scope

This is the VS Code adapter. The separate JetBrains Platform adapter and its
compatibility boundary are documented in [docs/INTELLIJ.md](../../docs/INTELLIJ.md).
