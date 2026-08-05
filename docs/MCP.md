# Local MCP inspection server

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

## Tools and resources

| Surface | Purpose | Authority |
| --- | --- | --- |
| `factory.status` | Local MCP boundary, version, and tool inventory | Read only |
| `factory.graph_ops` | Current deterministic Graph Ops snapshot | Read only |
| `factory.graph_impact` | Impact of 1–50 explicit root-relative changed paths | Read only |
| `factory.next_action` | One fact-derived next action | Read only |
| `factory://status` | The same status payload | Read only |
| `factory://graph` | The same Graph Ops payload | Read only |

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
