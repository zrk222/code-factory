# MCP Registry release lane

Code Factory ships a read-only, stdio MCP server over the same local Graph Ops
facts used by Studio and the IDE adapters. The candidate manifest is
[`../.mcp/server.json`](../.mcp/server.json).

## Current boundary

The manifest targets the published PyPI package `factoryline-code-factory` at
`0.28.0`. The package ownership marker is present in the root README, but the
registry entry is not claimed as published until the exact package metadata and
publisher authentication have both been verified.

The server is local and read-only. It does not grant process execution,
approval, publishing, deployment, signing, messaging, credentials, or network
authority.

## Release checklist

1. Build and publish the matching package version to PyPI.
2. Verify the published PyPI README contains exactly one
   `<!-- mcp-name: io.github.zrk222/code-factory -->` marker.
3. Validate `.mcp/server.json` against the current MCP Registry schema and
   publisher CLI.
4. Authenticate with GitHub in the publisher tool, then publish the manifest.
5. Verify the registry search result has the expected name, version, PyPI
   identifier, `uvx` runtime hint, and `stdio` transport.

Do not run a manual registry publish from a laptop with a copied token. The
publisher authentication belongs in a reviewed GitHub Actions environment with
OIDC and a matching package release.
