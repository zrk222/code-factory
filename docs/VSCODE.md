# FactoryLine for VS Code

The VS Code extension keeps the local proof loop close to the code you are
editing. It runs only a command you select, in the open trusted workspace, and
shows local JSON receipt fields next to the editor.

It does not upload the workspace, impersonate an approval, or certify a
release. The JetBrains adapter is documented separately in
[FactoryLine for JetBrains IDEs](INTELLIJ.md).

## Install

1. Install FactoryLine: `pip install factoryline-code-factory==0.17.3`.
2. Download a `factoryline-vscode-*.vsix` release asset, or build it from
   `editors/vscode` with `npm ci` then `npm run package`.
3. Run `code --install-extension factoryline-vscode-0.3.0.vsix`.
4. Open a trusted project folder and run a command from the Command Palette.

## Commands

| Command | Exact local action |
| --- | --- |
| `FactoryLine: Run Spec-to-Ship Assembly` | `factory assemble <feature> --root <workspace>` |
| `FactoryLine: Verify Feature Receipts` | `factory verify <feature> --root <workspace>` |
| `FactoryLine: Open Local Meter` | Reads `factory meter --root <workspace> --json` after workspace confirmation |
| `FactoryLine: Open Latest Receipt` | Renders JSON found below `.factory/` or `receipts/` |
| `FactoryLine: Open Local Factory Studio` | Opens the live dashboard plus target and deployment-route selectors after confirming workspace trust |
| `FactoryLine: Open Product Missions` | Uses the same confirmation and loopback boundary, then opens Studio at `?mode=product` for deterministic PRD-to-mission compilation |
| `FactoryLine: Open Requirement Evidence` | A CodeLens on `REQ-*`, `FR-*`, or `NFR-*` opens matching bounded local proof without executing a command |

Command output stays in the **FactoryLine** output channel. A successful command
opens the newest available receipt as a read-only local webview. Configure
`factoryline.command` only when the `factory` executable is not on VS Code's
PATH.

Factory Studio is a local development surface. The extension terminates its
Studio child process when the extension or workspace is disposed. It does not
grant deploy, publish, signing, credential, connector, or external-message
authority. Product Missions additionally require execution approval and emit
no merge or promotion authority.

Requirement evidence navigation searches only `.factory`, `receipts`,
`coverage`, `tests`, and `specs`, skips dependency/build trees, ignores files
larger than 2 MB, and inspects at most 2,000 candidate files per action.
