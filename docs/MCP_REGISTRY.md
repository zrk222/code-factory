# Official MCP Registry

Code Factory is published to the Official MCP Registry as
`io.github.zrk222/code-factory`. The registry package entry uses the public
PyPI distribution `factoryline-code-factory==0.45.0` and starts the existing
local stdio adapter through `uvx`:

**Use it to give an AI coding client read-only facts about declared intent,
test challenges, Graph Ops, and review evidence—without handing that client
write or release authority.**

```text
uvx --from factoryline-code-factory==0.45.0 factory mcp serve
```

The server needs a workspace root. Configure that explicit path in a client
that supports local stdio MCP, or use the existing configuration renderer:

```powershell
factory mcp config --client generic --root C:\work\my-mvp --json
```

## What it exposes

The server returns bounded, deterministic local facts: Graph Ops, path-scoped
proof impact, receipts, verifier and contradiction status, source-bound Intake
and Proof-Delta status, existing Gauntlet Survival Card status, a redacted
Developer Memory Brief, and hash-only LangGraph assurance facts. It never uploads source,
starts a worker, runs a graph, writes files, executes a repair, approves work,
publishes, deploys, signs, sends a message, or accesses credentials.

The registry descriptor has `stdio` transport only and contains no environment
variables or remote endpoint. Your MCP client remains responsible for its own
installation, local-server approval, tool-call confirmation, and workspace
access controls. See [AI client connections](AI_CLIENTS.md) for Cursor,
OpenCode, Codex, and portable local setup examples, and [the MCP contract](MCP.md)
for tool schemas and failure behavior. The descriptor does not create a hosted
service, add write authority, or access credentials.

## Release boundary

Registry metadata is published from the GitHub release workflow only after the
same PyPI version is live and its long description contains this exact ownership
marker:

<!-- mcp-name: io.github.zrk222/code-factory -->

The workflow uses GitHub OIDC rather than a stored MCP Registry token. A
published registry descriptor makes the installation metadata discoverable; it
does not prove a particular AI client installed, approved, or used the server.
