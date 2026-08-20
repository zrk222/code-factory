# DeepSeek Harness adapter

Code Factory can be attached to [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)
through Harness's official generic MCP client. The adapter is a small opt-in
Cordis overlay, not a replacement agent runtime.

## Why this pairing is useful

DeepSeek Harness owns a model session and tool lifecycle. Code Factory adds a
separate local evidence surface around it:

```mermaid
flowchart LR
  harness["DeepSeek Harness agent"] --> bridge["Official DSH MCP client"]
  bridge --> facts["Code Factory local facts"]
  facts --> graph["Graph Ops and next proof"]
  facts --> license["Expiry-bound Earned Autonomy"]
  facts --> combine["Verified Combine scoreboard"]
  graph --> human["Named human decision"]
  license --> human
  combine --> human
```

The bridge exposes existing read-only MCP tools. It cannot invoke a Code
Factory worker, run a repair, raise an agent license, approve a change,
publish a package, deploy a service, sign an artifact, or obtain credentials.
Agent identities remain declared identifiers unless a separate governed harness
authenticates them.

## Install

Install the published Code Factory CLI and copy the versioned overlay from
[`plugins/code-factory-deepseek-harness`](../plugins/code-factory-deepseek-harness):

```sh
pip install "factoryline-code-factory>=0.40.2"
dsh web --patch /absolute/path/to/code-factory.cordis.yml
```

Run `dsh` from the workspace that the local MCP server may inspect. The overlay
starts the existing `factory mcp serve --root .` command through
`@deepseek-ai/dsh-mcp-client`. It neither installs a dependency nor uploads
source code.

## What the agent can read

- Graph Ops, receipt inventory, path impact, and the fact-derived next action;
- source-bound intake and verifier, Gauntlet, proof-delta, and CDTE status;
- redacted local Developer Memory / Continuity context; and
- local Earned Autonomy and Combine status, which remain evidence projections,
  not identity proof, authorization, or a vendor-quality benchmark.

The official DSH MCP bridge currently exposes MCP tools to the model. It does
not consume MCP resources or prompts, so `factory://status` and
`factory://graph` remain available to other MCP clients but are not surfaced
through this particular Harness adapter.

## Compatibility and discovery

DeepSeek Harness identifies itself as developer preview and warns that breaking
changes are expected. Treat the overlay as a versioned compatibility adapter
and validate it with the installed Harness before using it in a production
workflow.

At the time this adapter was added, DeepSeek's official repository documents
the public `dsh-plugin` GitHub topic as the plugin discovery path. It does not
document a separate official marketplace registration endpoint. Code Factory
therefore uses that official discovery mechanism and does not claim a listing
until one is confirmed by a marketplace or directory target.
