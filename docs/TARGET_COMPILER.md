# Target Compiler and Factory Studio

Code Factory can compile one prompt or UTF-8 PRD into one governed starter:

| Target | Generated runtime | Default model calls | Primary proof |
| --- | --- | ---: | --- |
| `worker` | Deterministic Python worker | 0 | Repeatable input/output smoke |
| `web` | Next.js plus FastAPI | Not claimed | Build, API health, product tests |
| `mobile` | Expo SDK 57 TypeScript plus FastAPI | Not claimed | Expo dependency check, typecheck, API health |
| `agent-ui` | Next.js operator UI plus FastAPI | Not claimed | Preview-only task boundary and required approval |

The compiler itself is deterministic and makes no model call. A generated app
can add a model later, but only through product-specific implementation,
connector review, runtime tests, and an explicit capability grant.

## CLI

Compile from a prompt:

```powershell
factory create "Build a receipt review workspace" `
  --target agent-ui `
  --out receipt-review `
  --purpose developer `
  --json
```

Compile from a PRD:

```powershell
factory create --prd .\PRD.md --target mobile --out .\mobile-client --json
```

Exactly one source is required. The output must be absent or empty. There is no
`--force` path: Code Factory will not replace an implemented project with a
generated starter.

## Generated contract

Every target contains:

- `target_manifest.json` using `factory.target.v1`.
- An SSAT architecture contract and non-hollow smoke hook.
- `.forge/<feature>/state.json` with promotion blocked.
- `.factory/target-architecture.mmd`.
- `.factory/target-compile-receipt.json` with exact source, manifest, and file
  SHA-256 values.

Deployment, publication, signing, destructive actions, connector grants,
credential injection, and external messages are not granted by generation.
The receipt proves what the compiler emitted; it does not prove the product is
complete or production ready.

## Local Studio

```powershell
factory studio --root .
factory studio --root . --check --json
```

Studio binds only to `127.0.0.1`, selects an available port by default, accepts
at most 64 KiB per create request, writes only a direct child of the selected
root, and does not serve arbitrary workspace files. It is a local development
surface built with Python's basic HTTP server, not a production web server.

The VS Code and JetBrains commands require workspace confirmation, start
`factory studio --port 0 --no-browser`, accept only a literal loopback URL, and
open that URL through the editor API. Closing the IDE project terminates the
child Studio process.

## Validation

```powershell
pytest -q
npm --prefix editors\vscode test
editors\intellij\gradlew.bat -p editors\intellij test
```

Generated projects should also run their own commands from `README.md`. For
Expo, use `npm install`, `npm run doctor`, and `npm run typecheck`; native
directories remain absent until Expo Continuous Native Generation creates them.

Official integration references:

- [Expo create-expo-app](https://docs.expo.dev/more/create-expo/)
- [Expo development process and CNG](https://docs.expo.dev/workflow/overview/)
- [VS Code remote and external URI behavior](https://code.visualstudio.com/api/advanced-topics/remote-extensions)
- [JetBrains opening links](https://plugins.jetbrains.com/docs/intellij/link.html)
- [Python HTTP server security boundary](https://docs.python.org/3/library/security_warnings.html)
