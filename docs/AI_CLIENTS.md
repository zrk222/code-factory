# AI client connections

Code Factory's local MCP server can supply bounded, receipt-backed proof
context to any coding assistant that supports local stdio MCP. The standard
connection is local, stdio-only, and read-only; Cursor, OpenCode, and Codex
have copy-only renderers below.

## Prerequisites

Install the published package in the same environment that the client can
launch, then verify the workspace boundary:

```powershell
python -m pip install factoryline-code-factory==0.37.0
factory mcp status --root C:\work\my-mvp --json
factory mcp config --client generic --root C:\work\my-mvp --json
```

Replace `C:\work\my-mvp` with the repository the client is allowed to inspect.
The directory must already exist. Keep the path explicit when the client may
open more than one workspace; this prevents an agent from silently inspecting
the wrong checkout.

## Any MCP-capable coding assistant

Use the generic renderer whenever the assistant accepts a local stdio MCP
command but is not listed below:

```powershell
factory mcp config --client generic --root C:\work\my-mvp --json
```

Copy its `connection` object into the assistant's documented MCP configuration.
The setup command only prints configuration; it never modifies the assistant,
starts a server, or writes into the workspace. If an assistant has no MCP
client, keep the same workspace boundary and ask it to propose explicit
`factory` CLI commands for a human to run and review.

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

## Codex

Render the locally installed Codex command, inspect it, then run it yourself if
you want the connection added to Codex's global MCP configuration:

```powershell
factory mcp config --client codex --root C:\work\my-mvp
```

The rendered command is equivalent to:

```powershell
codex mcp add code-factory -- factory mcp serve --root C:\work\my-mvp
```

This is still a local stdio server. It does not add a remote endpoint, share
source with a provider, or give Codex write, approval, release, credential, or
connector authority through MCP.

## What the connection provides

Every configured MCP client can inspect the same bounded surfaces:

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

## AI code-review tools

The MCP server stays independent of hosted review vendors. If a team uses
CodeRabbit or another AI code-review product, keep its suggestions in that
product's review surface and use the optional
[GitHub Proof Review](GITHUB_PROOF_REVIEW.md) workflow for FactoryLine's
deterministic changed-scope, proof-gap, and next-action packet. No provider
credential, AI comment, or model judgment is imported into a FactoryLine
receipt.

## Support boundary

**Proven now:** Code Factory's local stdio MCP server and its read-only tool
contract are implemented and tested. The generic, Cursor, OpenCode, and Codex
renderers produce deterministic local setup packets; each client must still
approve and operate that packet under its own controls.

**Not claimed:** universal support by clients that do not implement local
stdio MCP, automatic client configuration, a Cursor-specific extension listing,
a Cursor Marketplace publication, or a hosted MCP endpoint with OIDC. Use the
portable CLI handoff when a client lacks MCP support. A Cursor-specific extension smoke test is not part of the current CI matrix.

**Remote future path:** a hosted adapter would need its own authenticated
endpoint, tenant isolation, rate limits, audit receipts, and explicit
authorization. Do not replace the local command above with an unreviewed
remote URL.

See the underlying [local MCP contract](MCP.md) for the complete tool list,
input validation, and failure behavior.
