# Code Factory for DeepSeek Harness

An opt-in DeepSeek Harness overlay that exposes Code Factory's **local,
read-only proof layer** as native Harness tools. It is built around the official
`@deepseek-ai/dsh-mcp-client` bridge rather than a custom process runner.

## What it adds

When the overlay is active, DeepSeek Harness discovers the local Code Factory
MCP server and makes its tools available under a `mcp__code_factory__...`
namespace. The exact final function names are normalized by Harness from the
server's advertised names.

- inspect Graph Ops, proof impact, receipts, intake state, and local
  verifier/Survival Card facts;
- inspect expiry-bound Earned Autonomy evidence and verified Combine
  scoreboards; and
- request the next fact-derived action without invoking a worker, repair,
  release, deployment, signing operation, network connector, or credential.

Code Factory keeps its existing boundary: agent subjects are **declared
identifiers** unless a separately governed harness authenticates them. An
Earned Autonomy tier is a local admission cap—not an execution grant or a
vendor-quality claim.

## Install and run

1. Install Code Factory in the Python environment that will serve MCP:

   ```sh
   pip install "factoryline-code-factory>=0.40.2"
   ```

2. From the repository you want to inspect, start Harness with this opt-in
   patch:

   ```sh
   dsh web --patch /absolute/path/to/code-factory.cordis.yml
   ```

   The overlay uses `factory mcp serve --root .`, so Harness must be launched
   from the intended workspace. It does not install Python packages, create an
   account, select a model, configure credentials, or upload source code.

3. Wait for the MCP client to finish discovery, then ask the agent to inspect
   the current evidence before proposing a next action. For example:

   ```text
   Use the Code Factory Graph Ops facts and explain the smallest next proof.
   Do not execute or authorize anything.
   ```

## Verify the boundary

```sh
factory mcp status --root . --json
factory license status --root . --agent .factory/agent.json --json
factory combine status --root . --json
```

The Harness bridge currently exposes MCP **tools**, not MCP resources or
prompts. Tool discovery and reconnect behavior are provided by DeepSeek
Harness; Code Factory returns only bounded local data and does not supervise a
remote service.

## Compatibility

DeepSeek Harness is in developer preview and explicitly allows
compatibility-breaking changes. This overlay is therefore versioned with Code
Factory and validated as a declarative adapter. If DeepSeek changes the
`@deepseek-ai/dsh-mcp-client` configuration contract, update this overlay before
relying on it in a production workflow.

For public discoverability, the Code Factory GitHub repository should carry the
`dsh-plugin` topic. The official DeepSeek Harness repository documents that
topic as its current plugin-discovery path; it does not document a separate
official marketplace submission API.
