# AI client connections

Code Factory's local MCP server can supply bounded, receipt-backed proof
context to both Cursor and OpenCode. This is the supported connection path for
these clients today: it is local, stdio-only, and read-only.

## Prerequisites

Install the published package in the same environment that the client can
launch, then verify the workspace boundary:

```powershell
python -m pip install factoryline-code-factory==0.28.0
factory mcp status --root C:\work\my-mvp --json
```

Replace `C:\work\my-mvp` with the repository the client is allowed to inspect.
The directory must already exist. Keep the path explicit when the client may
open more than one workspace; this prevents an agent from silently inspecting
the wrong checkout.

## Cursor

Cursor reads project MCP configuration from `.cursor/mcp.json`. Create that
file at the root of the project you want Cursor to inspect:

```json
{
  "mcpServers": {
    "code-factory": {
      "command": "factory",
      "args": ["mcp", "serve", "--root", "C:\\work\\my-mvp"]
    }
  }
}
```

Open the project in Cursor and approve the local server when prompted. Cursor
uses MCP approval controls by default; do not enable automatic tool execution
for a workspace that should remain human-controlled. Cursor's CLI can use the
same project MCP configuration for headless runs, but the `--force` option is
outside this read-only Code Factory boundary and must be governed separately.

## OpenCode

OpenCode uses an `mcp` object in `opencode.json` (or
`.opencode/opencode.json`). Put this file in the project root:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "code-factory": {
      "type": "local",
      "command": [
        "factory",
        "mcp",
        "serve",
        "--root",
        "C:\\work\\my-mvp"
      ],
      "enabled": true,
      "timeout": 5000
    }
  }
}
```

OpenCode will make the local MCP tools available to the session. Keep
`enabled` explicit and use the same root path you verified with
`factory mcp status`.

## What the connection provides

Both clients can inspect the same bounded surfaces:

- `factory.status` and `factory.graph_ops` for current delivery facts;
- `factory.graph_impact` and `factory.next_action` for path-scoped guidance;
- receipt inventory and exact receipt lookup;
- verifier, proof-reuse, CDTE, PRD Grill, and workspace-advisor status; and
- `factory://status` and `factory://graph` resources.

The tools are read-only, idempotent, and closed-world. They do not start
workers, modify files, execute shell commands, access provider keys, call
connectors, approve missions, publish releases, deploy services, sign
artifacts, or send messages. A client can propose or explain the next step,
but the existing human-controlled CLI and release gates remain authoritative.

## Support boundary

**Proven now:** Code Factory's local stdio MCP server and its read-only tool
contract are implemented and tested; Cursor and OpenCode both document native
local MCP configuration.

**Not claimed:** a Cursor-specific extension listing, a Cursor Marketplace
publication, or a hosted MCP endpoint with OIDC. Cursor is VS Code-based, but a
Cursor-specific extension smoke test is not part of the current CI matrix. The
VS Code extension may be evaluated separately; use MCP when you need the
portable proof-context path.

**Remote future path:** a hosted adapter would need its own authenticated
endpoint, tenant isolation, rate limits, audit receipts, and explicit
authorization. Do not replace the local command above with an unreviewed
remote URL.

See the underlying [local MCP contract](MCP.md) for the complete tool list,
input validation, and failure behavior.
