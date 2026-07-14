# FactoryLine for VS Code

The VS Code extension keeps the local proof loop close to the code you are
editing. It runs only a command you select, in the open trusted workspace, and
shows local JSON receipt fields next to the editor.

It does not upload the workspace, impersonate an approval, or certify a
release. The JetBrains adapter is documented separately in
[FactoryLine for JetBrains IDEs](INTELLIJ.md).

## Install

1. Install FactoryLine: `pip install factoryline-code-factory==0.13.0`.
2. Download a `factoryline-vscode-*.vsix` release asset, or build it from
   `editors/vscode` with `npm ci` then `npm run package`.
3. Run `code --install-extension factoryline-vscode-0.1.0.vsix`.
4. Open a trusted project folder and run a command from the Command Palette.

## Commands

| Command | Exact local action |
| --- | --- |
| `FactoryLine: Run Spec-to-Ship Assembly` | `factory assemble <feature> --root <workspace>` |
| `FactoryLine: Verify Feature Receipts` | `factory verify <feature> --root <workspace>` |
| `FactoryLine: Open Latest Receipt` | Renders JSON found below `.factory/` or `receipts/` |

Command output stays in the **FactoryLine** output channel. A successful command
opens the newest available receipt as a read-only local webview. Configure
`factoryline.command` only when the `factory` executable is not on VS Code's
PATH.
