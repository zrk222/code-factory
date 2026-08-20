# Code Factory 0.39.1

## Official MCP Registry distribution

Code Factory 0.39.1 makes the existing local, read-only MCP adapter
discoverable as `io.github.zrk222/code-factory` in the Official MCP Registry.
The entry launches the verified public package with:

```text
uvx --from factoryline-code-factory==0.39.1 factory mcp serve
```

It exposes the same bounded facts already available through the CLI: Graph Ops,
path-scoped proof impact, receipts, verifier and CDTE status, redacted
Developer Memory facts, and hash-only LangGraph assurance. It contains no
environment variables or remote endpoint.

The release pipeline validates the descriptor, waits for the matching PyPI
package and ownership marker, then publishes it with GitHub OIDC. It does not
store an MCP Registry token.

## Boundary

This release does not add a hosted service, automatic client configuration,
source upload, file writes, worker execution, repair execution, approval,
merge, deployment, publication, signing, credential access, connector calls, or
external messaging. Registry publication makes install metadata discoverable;
it does not prove that a specific client installed, approved, or used the
server.
