# Local MCP proof-context server

Code Factory exposes its existing local Graph Ops facts through a small,
stdio-only MCP server. It gives an agent exact delivery-state context without
creating a second graph model or granting any authority.

```powershell
factory mcp status --root . --json
factory mcp config --client generic --root .my-mvp --json
factory mcp serve --root .my-mvp
```

The server accepts newline-delimited JSON-RPC on standard input and writes
responses only to standard output. It does not use HTTP, SSE, OAuth, network
egress, credentials, connector grants, process execution, approval, publishing,
deployment, signing, or messaging.

## Connect a local MCP client

Point a client at the installed `factory` command and use the workspace the
agent is allowed to inspect. For example:

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

The `--root` directory must already exist. The server will not create it.

## Any coding assistant: one portable connection

Code Factory is not tied to one model or IDE. Any assistant that supports a
local stdio MCP server can use the same proof-context connection. Render a
copy-only setup packet first:

```powershell
factory mcp config --client generic --root C:\work\my-mvp --json
```

The generic packet contains only the standard command and arguments:

```json
{
  "command": "factory",
  "args": ["mcp", "serve", "--root", "C:\\work\\my-mvp"]
}
```

Paste that connection into the assistant's documented local-MCP setting and
approve it under that assistant's own controls. Code Factory does not write a
client config, enable automatic tool execution, or grant the assistant any
authority beyond the read-only tools below. An assistant without MCP support
can still use the same explicit CLI commands in a human-reviewed terminal.

Built-in renderers avoid client-specific guesswork:

```powershell
factory mcp config --client cursor --root C:\work\my-mvp
factory mcp config --client opencode --root C:\work\my-mvp
factory mcp config --client codex --root C:\work\my-mvp
```

The Codex renderer prints one `codex mcp add` command for the user to review
and run. It does not alter `config.toml` itself.

For an IDE-managed workspace configuration, keep the root local and let the
client substitute its current project directory:

```json
{
  "mcpServers": {
    "factoryline": {
      "command": "factory",
      "args": ["mcp", "serve", "--root", "${workspaceFolder}"]
    }
  }
}
```

This is a proof-context connection, not an AI-provider connection. Code Factory
does not call JetBrains AI, send source code to a provider, consume provider
credits, or turn on BYOK on the user's behalf.

### Cursor and OpenCode

Cursor and OpenCode can use this same local proof-context server without a
client-specific plugin. See [AI client connections](AI_CLIENTS.md) for the
exact `.cursor/mcp.json` and `opencode.json` snippets. The connection remains
local and read-only; client support does not add provider credentials,
network transport, or mutation authority.

## Tools and resources

| Surface | Purpose | Authority |
| --- | --- | --- |
| `factory.status` | Local MCP boundary, version, and tool inventory | Read only |
| `factory.graph_ops` | Current deterministic Graph Ops snapshot | Read only |
| `factory.graph_impact` | Impact of 1–50 explicit root-relative changed paths | Read only |
| `factory.developer_memory` | Exact-diff next-proof guidance with redacted continuity facts and observed local Git contribution context | Read only |
| `factory.langgraph_assurance` | Compare two existing local LangGraph transition receipts; returns parity or a hash-only incident capsule | Read only |
| `factory.next_action` | One fact-derived next action | Read only |
| `factory.list_receipts` | Bounded local receipt inventory; entries remain unassessed | Read only |
| `factory.get_receipt` | One local receipt by path or exact feature identifier | Read only |
| `factory.verifier_status` | A verifier-session boundary with unknown worker/verifier evidence left explicit | Read only |
| `factory.proof_reuse` | Fails closed until a complete explicit proof request can establish a disposition | Read only |
| `factory.proof_delta_status` | Existing retry-admission evidence; never admits, starts, or repairs a retry | Read only |
| `factory.cdte_status` | Latest existing deterministic CDTE scan; never creates a scan record | Read only |
| `factory.prd_grill_status` | Existing source-bound PRD Grill state for the supplied PRD | Read only |
| `factory.intake_status` | Existing source-bound framework, intent, acceptance, and external-effects intake state | Read only |
| `factory.gauntlet_status` | Existing local Survival Card facts, including whether only redacted verified Continuity metadata was bound; never compiles, admits, runs, signs, or promotes a batch | Read only |
| `factory.agent_license_status` | Current expiry-bound, local Earned Autonomy evidence for declared agents; never authenticates identity, records a run, issues a license, raises autonomy, or starts an agent | Read only |
| `factory.combine_status` | Existing locally verified Combine scoreboards for completed governed runs; never launches a candidate or creates a vendor-quality claim | Read only |
| `factory.workspace_advisor` | Bounded local workspace shape and path-only Remote/WSL preflight; no report artifacts are written through MCP | Read only |
| `factory://status` | The same status payload | Read only |
| `factory://graph` | The same Graph Ops payload | Read only |

Every tool declares MCP read-only, non-destructive, idempotent, and closed-world
hints. Root-relative path input is mandatory; absolute paths and parent
traversal fail with JSON-RPC `-32602`.

## Explicit gaps versus explicit contradictions

`factory.prd_grill_status` helps an agent see the current bounded clarification
frontier. It does not answer questions, edit a PRD, or approve implementation.
`factory.gauntlet_status` helps an agent read whether an already recorded,
human-admitted batch survived, went hollow, or was blocked, and whether the
card bound redacted verified Continuity metadata. It does not create an E2E
command from prose, execute a Gauntlet, retrieve memory contents, or turn a
card into a release decision.
`factory.cdte_status` reads an existing deterministic Conflict Detection and
Trade-off Engine record. A fresh CDTE scan creates a receipt and can fail a CI
gate, so the agent must request that command explicitly instead of causing it
through MCP.

This preserves the division of responsibility: PRD Grill and SpecLine surface
and resolve ambiguity with a human; CDTE records known constraint conflicts;
FactoryLine supplies the local facts to an AI client without granting it
execution, approval, publishing, deployment, signing, messaging, credential,
or connector authority.

`factory.workspace_advisor` is also intentionally advisory: it measures only
the local filesystem and path context. It does not query an IDE, connect to
WSL/Gateway/Docker/SSH, or change heap, caches, indexes, inspections, or
settings. See [Workspace Load Advisor](WORKSPACE_ADVISOR.md).

Tool and resource payloads are canonical UTF-8 JSON embedded in MCP text
content. The graph and impact tools directly call the same native functions as
the local CLI and Studio; no command is executed on a caller’s behalf.

`FACTORY_MCP_LOCAL_READ_ONLY` and `MCP_STDLIB_ONLY` make the boundary explicit.
Malformed requests, parent traversal, absolute changed paths, unknown tools,
and absent workspace roots fail with JSON-RPC `-32602`; unknown methods fail
with `-32601`.

## Generated output maps

Every completed `factory create`, `factory mvp`, and `factory app` starter now
contains `docs/CODE_FACTORY_OUTPUT_MAP.md`. The deterministic Mermaid map lists
every generated file, its source digest prefix, and the blocked promotion
state. It is an inventory and proof-boundary aid—not a claim that the product,
coverage, or production readiness is complete.

The target compiler also binds the map path and SHA-256 into
`.factory/target-compile-receipt.json`.
