# Local MCP proof-context server

Code Factory exposes its existing local Graph Ops facts through a small,
stdio-only MCP server. It gives an agent exact delivery-state context without
creating a second graph model or granting any authority.

```powershell
factory mcp status --root . --json
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

## Tools and resources

| Surface | Purpose | Authority |
| --- | --- | --- |
| `factory.status` | Local MCP boundary, version, and tool inventory | Read only |
| `factory.graph_ops` | Current deterministic Graph Ops snapshot | Read only |
| `factory.graph_impact` | Impact of 1–50 explicit root-relative changed paths | Read only |
| `factory.next_action` | One fact-derived next action | Read only |
| `factory.list_receipts` | Bounded local receipt inventory; entries remain unassessed | Read only |
| `factory.get_receipt` | One local receipt by path or exact feature identifier | Read only |
| `factory.verifier_status` | A verifier-session boundary with unknown worker/verifier evidence left explicit | Read only |
| `factory.proof_reuse` | Fails closed until a complete explicit proof request can establish a disposition | Read only |
| `factory.cdte_status` | Latest existing deterministic CDTE scan; never creates a scan record | Read only |
| `factory.prd_grill_status` | Existing source-bound PRD Grill state for the supplied PRD | Read only |
| `factory.workspace_advisor` | Bounded local workspace shape and path-only Remote/WSL preflight; no report artifacts are written through MCP | Read only |
| `factory://status` | The same status payload | Read only |
| `factory://graph` | The same Graph Ops payload | Read only |

Every tool declares MCP read-only, non-destructive, idempotent, and closed-world
hints. Root-relative path input is mandatory; absolute paths and parent
traversal fail with JSON-RPC `-32602`.

## Explicit gaps versus explicit contradictions

`factory.prd_grill_status` helps an agent see the current bounded clarification
frontier. It does not answer questions, edit a PRD, or approve implementation.
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
