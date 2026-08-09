# VS Code Marketplace release lane

This repository now has a guarded, evidence-first release lane for the
FactoryLine VS Code extension. It deliberately separates building a verified
candidate from publishing it.

## Candidate validation

Run the `Publish VS Code Marketplace extension` workflow with:

- `release_ref`: an immutable tag such as `v0.28.0`;
- `publish`: `false`.

The workflow checks the tag-to-commit binding, installs the locked Node
dependencies, runs the audit and extension tests, packages a VSIX, and uploads
a SHA-256-sealed candidate artifact.

## Protected publication

To publish, configure a GitHub Actions environment named `vscode-marketplace`
with a least-privilege `VSCE_PAT` secret, then dispatch the same workflow with
`publish: true`. The environment review and token are intentionally not
embedded in the repository or accepted from a developer laptop.

The publisher identity in `editors/vscode/package.json` is `zrk222`; the
Marketplace publisher must exist in the Visual Studio Marketplace publisher
portal and the token must have only the extension-publishing scope. The VSIX
is published only after the sealed candidate is re-hashed in the publish job.

Official guidance: [Publishing Extensions](https://code.visualstudio.com/api/working-with-extensions/publishing-extension).

## Current boundary

Adding this lane does not claim a Marketplace listing. A live listing requires
the protected `VSCE_PAT`, publisher account setup, and an approved action-time
dispatch. Until those are present, the honest state is **candidate prepared**.
