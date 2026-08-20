# AI client connections

Code Factory's local MCP server can supply bounded, receipt-backed proof
context to any coding assistant that supports local stdio MCP. The standard
connection is local, stdio-only, and read-only; Cursor, OpenCode, and Codex
have copy-only renderers below.

## Prerequisites

Install the published package in the same environment that the client can
launch, then verify the workspace boundary:

```powershell
python -m pip install factoryline-code-factory==0.40.2
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

The same local entry is discoverable as
[`io.github.zrk222/code-factory`](MCP_REGISTRY.md) in the Official MCP Registry.
Registry discovery resolves the public PyPI package and local stdio command; it
does not create a hosted endpoint, configure a client, or expand authority.

## JetBrains AI Assistant

JetBrains documents custom MCP-server integration for AI Assistant in supported
versions, alongside team Project Rules and `.aiignore` controls. FactoryLine
can supply the MCP portion as a **local stdio, read-only** proof-context server:

```powershell
factory mcp config --client generic --root C:\work\my-mvp --json
```

Copy the rendered `connection` object into the AI Assistant MCP setting that
your installed JetBrains version exposes, then approve it under JetBrains'
own controls. The available tools project receipts, Graph Ops, proof impact,
and next-action facts; they cannot run a worker, apply a repair, approve,
merge, publish, deploy, sign, message, access credentials, or upload source.

FactoryLine does **not** detect, configure, or enable JetBrains AI Assistant;
create Project Rules; edit `.aiignore`; select a model; consume AI credits; or
claim that a client has actually invoked a tool. Use Project Rules and
`.aiignore` for their intended JetBrains-side policy role, then use the local
FactoryLine receipts as grounded review context.

See JetBrains' [AI Assistant update details](https://plugins.jetbrains.com/plugin/22282-jetbrains-ai-assistant/versions/stable/977950)
and [MCP documentation](https://www.jetbrains.com/help/ai-assistant/mcp.html)
for availability in your IDE and subscription; those controls remain
JetBrains-managed.

## DeepSeek Harness

DeepSeek Harness can load the included opt-in Cordis overlay through its
official MCP client bridge:

```sh
dsh web --patch /absolute/path/to/plugins/code-factory-deepseek-harness/code-factory.cordis.yml
```

Launch Harness from the workspace to inspect. The adapter starts
`factory mcp serve --root .` locally and exposes the same read-only evidence
tools after Harness completes discovery. It does not configure a model,
credential, remote endpoint, automatic execution, or an identity provider.
Read [the adapter guide](DEEPSEEK_HARNESS.md) before enabling it; Harness is in
developer preview and may change this configuration contract.

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
- `factory.developer_memory` for a capped, exact-diff next-proof brief with
  redacted Continuity facts and observed local Git contribution context;
- `factory.gauntlet_status` for read-only Survival Card facts, including
  whether a card bound only redacted verified Continuity metadata; and
- `factory.langgraph_assurance` for a hash-only comparison of two already
  recorded LangGraph transition receipts; it never invokes the graph;
- `factory.agent_license_status` and `factory.combine_status` for current local
  Earned Autonomy evidence and verified scoreboards; they do not authenticate
  an agent, issue a license, start a candidate, or rank a vendor; and
- receipt inventory and exact receipt lookup;
- verifier, proof-reuse, Proof-Delta, Gauntlet Survival Card, CDTE, PRD Grill,
  Intake Grill, and workspace-advisor status; and
- `factory://status` and `factory://graph` resources.

The tools are read-only, idempotent, and closed-world. They do not start
workers, modify files, execute shell commands, access provider keys, call
connectors, approve missions, publish releases, deploy services, sign
artifacts, or send messages. A client can propose or explain the next step,
but the existing human-controlled CLI and release gates remain authoritative.

`factory.gauntlet_status` reads existing local Survival Cards only. An MCP
client cannot use it to compile a command from prose, admit or rerun a batch,
apply a repair, or turn a card into a release decision. See
[Gauntlet](GAUNTLET.md) for the separate human-controlled CLI path.

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
