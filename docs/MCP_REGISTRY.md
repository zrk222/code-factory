# Official MCP Registry

Code Factory is published to the Official MCP Registry as
`io.github.zrk222/code-factory`. The registry package entry uses the public
PyPI distribution `factoryline-code-factory==0.46.8` and starts the existing
local stdio adapter through `uvx`:

**Use it to give an AI coding client read-only facts about declared intent,
test challenges, Graph Ops, and review evidence—without handing that client
write or release authority.**

```text
uvx --from factoryline-code-factory==0.46.8 factory mcp serve
```

The 0.46.9 candidate package coordinate is
`uvx --from factoryline-code-factory==0.46.9 factory mcp serve`. It is not
published yet; keep using the 0.46.8 command above until the protected release
gates and publication complete.

The server needs a workspace root. Configure that explicit path in a client
that supports local stdio MCP, or use the existing configuration renderer:

```powershell
factory mcp config --client generic --root C:\work\my-mvp --json
```

## What it exposes

The server returns bounded, deterministic local facts: Graph Ops, path-scoped
proof impact, receipts, verifier and contradiction status, source-bound Intake
and Proof-Delta status, existing Gauntlet Survival Card status, a redacted
Developer Memory Brief, hash-only LangGraph assurance facts, and the shared
Control Plane status (Oracle Firewall, Operations Control, Session Trace, and
Proof-gated Repair Loop). It never uploads source,
starts a worker, runs a graph, writes files, executes a repair, approves work,
publishes, deploys, signs, sends a message, or accesses credentials.

The source inventory also includes `factory.project_scope_review`, which reads
bounded, workspace-relative PRD/spec Markdown and routes matching scope to the
existing AppForge and provider-neutral SaaS proof status projections. The
published registry entry remains on 0.46.8 until a protected 0.46.9 release
publishes the matching candidate descriptor. This branch's additional tool is
not available from the live registry yet.

The registry descriptor has `stdio` transport only and contains no environment
variables or remote endpoint. Your MCP client remains responsible for its own
installation, local-server approval, tool-call confirmation, and workspace
access controls. See [AI client connections](AI_CLIENTS.md) for Cursor,
OpenCode, Codex, and portable local setup examples, and [the MCP contract](MCP.md)
for tool schemas and failure behavior. The descriptor does not create a hosted
service, add write authority, or access credentials.

## Muse Code plugin catalog

The repository's [Claude-compatible plugin catalog](../.claude-plugin/marketplace.json)
also includes `expertise-agent-workflows` and `code-factory-build-audit`. Muse
Code's marketplace importer accepts Claude catalogs and reads the packages'
native `.muse-plugin/plugin.json` manifests. The Expertise plugin exposes three distinct
MCP tools—Earnie vendor value review, Cluso account impact review, and Surely
portfolio watch—through one Muse skill. Its local stdio router selects a
workflow contract only; it does not access Expertise.ai or the remote agents'
backends. On a plugin-capable host, review and approve its MCP server and the
build-audit hooks before relying on them in a new session.

After the catalog change is available from the selected Git ref, the local
installation flow is:

```text
muse plugins marketplace add code-factory https://github.com/zrk222/code-factory#codex/release-governance-self-audit
muse plugins list --available
muse plugins install expertise-agent-workflows@code-factory
muse plugins inspect expertise-agent-workflows
muse plugins approve expertise-agent-workflows
```

This machine's Muse Code 1.3.0 build reports that plugin-management commands are
unavailable. Its supported standalone extension points remain usable. Install
the same two skills, post-build hooks, and Expertise MCP tools with:

```text
node scripts/install_muse_extensions.mjs
muse skills list --source user
```

The installer preserves unrelated `settings.json` entries, copies managed
runtime files under the Muse config directory, and registers a user-level stdio
server. The post-build hook runs in Muse shell sessions; the three workflow
tools are available to Muse sessions that load the user's MCP settings. Each
MCP tool call still follows Muse's ordinary approval flow. Use the standalone
path while the installed build lacks the plugin command; a plugin-capable build
can install and review the native packages from the catalog above.

This is a team-hosted Muse Code plugin catalog, not an entry in the Official
MCP Registry and not Meta approval or a listing in the consumer Muse connector
directory. Meta's [Muse Connector Platform](https://muse.ai/platform) describes
a functional, security, legal, and end-to-end review. The [Meta AI Connectors
developer page](https://dev.meta.ai/products/connectors) describes an early
access path for a live REST API (or one in active development), a clear use
case, and account linking. Meta says developer access is selected in waves and
public publishing/discovery comes later.

The current packages use local stdio and do not provide a hosted HTTPS API,
OAuth account linking, public support route, or connector-specific terms and
privacy package. The appropriate next step is not a claim of approval: build and
operate that hosted service, verify its end-to-end flows, then submit the real
endpoint and legal/contact details through Meta's connector process.

Candidate requests for user research—not evidence of market demand—include:

- “Compare this renewal with the dated pricing records I provide, and show
  what is missing before I speak to the vendor.”
- “Summarize verified signals for this customer account since my review date,
  and separate facts from items that need checking.”
- “Which sites should I ask an operator about after these official alerts? Do
  not label a site affected without confirmation.”

These are focused business workflows, not proven mass-market consumer use
cases. They serve a different purpose from Junie; no superiority claim is
supported by current evidence.

## Release boundary

Registry metadata is published from the GitHub release workflow only after the
same PyPI version is live and its long description contains this exact ownership
marker:

<!-- mcp-name: io.github.zrk222/code-factory -->

The workflow uses GitHub OIDC rather than a stored MCP Registry token. A
published registry descriptor makes the installation metadata discoverable; it
does not prove a particular AI client installed, approved, or used the server.
