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

## One-shot stateless request

Use the stateless path when a caller needs exactly one bounded request and
cannot retain an MCP session:

```powershell
factory mcp request requests\status.json --root C:\work\my-mvp --json
```

The request file must be a workspace-relative UTF-8 JSON file containing one
JSON-RPC object with only the core `jsonrpc`, `id`, `method`, and `params`
fields. Session IDs, cursors, state extensions, absolute paths, parent
traversal, and payloads larger than 65,536 bytes fail closed. The response is
wrapped in `factory.mcp.stateless-response.v1`, marked
`MCP_STATELESS_RESPONSE`, and binds the canonical request with
`request_sha256`. No request history or server state is retained. This is a
local read-only evaluation of the existing MCP handlers, not a hosted HTTP
endpoint, and it adds no execution, approval, release, deployment, signing,
credential, connector, or provider authority.

Each stateless envelope also includes `MCP_STATELESS_REPLAY_HINTS`. The
`requestKey` and `responseSha256` let an IDE or CI client deduplicate its own
retry work and compare a fresh response; successful read-only responses carry
a 300-second client cache hint, while errors and notifications are never
cacheable. This is deliberately client-side guidance: Code Factory keeps no
replay ledger, does not promise server-side deduplication, and requires a
fresh request for revalidation.

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
| `factory.first_lap_status` | First Lap mission, journey, holdout, and generated-file integrity status | Read only |
| `factory.agui_review_events` | Bounded AGUI-style review cards and human-interrupt events derived from local First Lap status | Read only |
| `factory.graph_ops` | Current deterministic Graph Ops snapshot | Read only |
| `factory.graph_impact` | Impact of 1–50 explicit root-relative changed paths | Read only |
| `factory.developer_memory` | Exact-diff next-proof guidance with redacted continuity facts and observed local Git contribution context | Read only |
| `factory.langgraph_assurance` | Compare two existing local LangGraph transition receipts; returns parity or a hash-only incident capsule | Read only |
| `factory.next_action` | One fact-derived next action | Read only |
| `factory.list_receipts` | Bounded local receipt inventory; entries remain unassessed | Read only |
| `factory.get_receipt` | One local receipt by path or exact feature identifier | Read only |
| `factory.verifier_status` | A verifier-session boundary with unknown worker/verifier evidence left explicit | Read only |
| `factory.proof_reuse` | Fails closed until a complete explicit proof request can establish a disposition | Read only |
| `factory.context_efficiency_status` | Bounded context-packet/cache metadata and estimated token budget; no provider-usage or savings claim | Read only |
| `factory.intake_parameters_status` | Bounded intake mode, risk, budget, scope, provenance, expiry, and canonical six-lane coverage | Read only |
| `factory.search_audit_rules` | Context-bounded search over six-lane rejection conditions and required evidence; never executes a lane | Read only |
| `factory.proof_delta_status` | Existing retry-admission evidence; never admits, starts, or repairs a retry | Read only |
| `factory.cdte_status` | Latest existing deterministic CDTE scan; never creates a scan record | Read only |
| `factory.prd_grill_status` | Existing source-bound PRD Grill state for the supplied PRD | Read only |
| `factory.intake_status` | Existing source-bound framework, intent, acceptance, and external-effects intake state | Read only |
| `factory.gauntlet_status` | Existing local Survival Card facts, including whether only redacted verified Continuity metadata was bound; never compiles, admits, runs, signs, or promotes a batch | Read only |
| `factory.agent_license_status` | Current expiry-bound, local Earned Autonomy evidence for declared agents; never authenticates identity, records a run, issues a license, raises autonomy, or starts an agent | Read only |
| `factory.combine_status` | Existing locally verified Combine scoreboards for completed governed runs; never launches a candidate or creates a vendor-quality claim | Read only |
| `factory.workspace_advisor` | Bounded local workspace shape and path-only Remote/WSL preflight; no report artifacts are written through MCP | Read only |
| `factory.revenue_status` | Current hash-verified RevenueForge receipts and fail-closed purchase, TestFlight, failure-matrix, policy-drift, and memory evidence state | Read only |
| `factory.revenue_memory` | Exact-app, exact-journey, expiry-aware approved evidence-memory guidance; never substitutes prior evidence for the current build | Read only |
| `factory.appforge_status` | Current hash-verified AppForge design contracts and storyboard state; never renders, approves, submits, or deploys an app | Read only |
| `factory.oracle_firewall_status` | Sealed source-to-decision Oracle Firewall contracts, weakening reports, independent challenge receipts, and incidents; never seals, approves, challenges, repairs, or releases work | Read only |
| `factory.proof_continuity_status` | Repository-level source-to-obligation-to-forbidden-behavior-to-gate-to-test-to-evidence audit continuity and reopened incidents; never runs evidence collection, changes code, releases, or approves work | Read only |
| `factory.appforge_oracle_status` | Candidate-bound AppForge Oracle authority receipts; never changes policy sources, media, reviewers, TestFlight, or App Store Connect | Read only |
| `factory.appforge_device_reality_status` | Sealed AppForge device-intent and supervised-capture receipts; never starts Phone Harness, controls a device, accesses credentials, or contacts Apple | Read only |
| `factory.appforge_release_rehearsal_status` | Candidate-bound credential-free Fastlane, App Store Connect CLI, Cider, Swiftlane, or Zealot rehearsal receipts; never invokes a provider, accesses credentials, uploads, contacts Apple, or submits a release | Read only |
| `factory.appforge_native_surface_status` | Candidate-bound static Swift adaptive-surface, accessibility, material-budget, and storyboard receipt state; never builds, renders, operates a device, downloads assets, or contacts Apple | Read only |
| `factory.appforge_surface_matrix_status` | Candidate-bound iPhone/iPad and accessibility configuration plan; never starts a simulator, controls hardware, captures screenshots, or contacts Apple | Read only |
| `factory.appforge_storefront_story_status` | Candidate-bound Store screenshot journey, story, and local claim-reference state; never generates images, uploads media, contacts Apple, or submits a release | Read only |
| `factory.appforge_fastlane_capture_status` | Candidate-bound Fastlane Snapshot capture contract state; never runs Fastlane/Xcode, controls a simulator or device, accesses credentials, uploads media, contacts Apple, or submits a release | Read only |
| `factory.codex_metadata_audit` | Privacy-safe workspace metadata audit of declared local run-state files; never imports prompts, tool output, credentials, provider history, or home-directory Codex records | Read only |
| `factory://status` | The same status payload | Read only |
| `factory://graph` | The same Graph Ops payload | Read only |

Every tool declares MCP read-only, non-destructive, idempotent, and closed-world
hints. Root-relative path input is mandatory; absolute paths and parent
traversal fail with JSON-RPC `-32602`.

### First Lap discovery

`factory.first_lap_status` is the lowest-cost starting point for a new agent or
IDE integration. It verifies only the initialization receipt and the hashes of
`MISSION.md`, `END-TO-END.md`, and `.factory/holdouts/HOLDOUT.md`; it does not
open the holdout, run tests, execute a journey, or infer readiness. A
`NOT_INITIALIZED` result points to `factory first-lap init --root .`; a
`BLOCKED` result identifies stale or missing generated files and tells the
operator to restore or re-initialize them before calibration. The same
read-only projection is available as `factory.first_lap_status` in the
progressive WebMCP manifest.

### AGUI review events

`factory.agui_review_events` is the compact presentation bridge for Mission
Control and IDE clients. It emits a controlled `RUN_STARTED` →
`STATE_SNAPSHOT` → `REVIEW_CARD` → `RUN_FINISHED` stream with stable event and
payload hashes. Clients may map the declarative `ReviewCard` hint to their own
UI catalog; no generated component is executed by Code Factory. MCP2
`input_required` and `completed` release-gate envelopes can be projected to
the same `INTERRUPT` and `RUN_FINISHED` shapes by `factoryline.agui` while
keeping release authority human-owned. The adapter is local and read-only; it
does not claim a full external AGUI transport or open-ended generative UI.

### Proof-Delta halt telemetry

The `factory.graph_ops` response includes `proof_delta_telemetry` records for
each verified retry packet. A `NO_GAIN_HALT` record is bound to the exact
candidate and evidence digests and includes the blocker type, candidate/evidence
change flags, unresolved proof debt, and one fact-derived next action. The same
record is projected as a `proof_delta_guard` node plus blocker, evidence,
candidate, debt, and next-action edges in the Mermaid graph. This is an
inspectable explanation of why a retry stopped; it never retries, executes,
edits, approves, or publishes work.

### MCP2-style human gate handoff

`factory.release_decision` returns an `mcp2` `input_required` envelope with a
deterministic `toolCallId`, explicit failed-lane findings, a minimal reviewer
decision schema, the hash of the local proof card, unresolved proof debt, and
the next fact-derived action. The envelope is safe to hand to a stateless HTTP
bridge: the connection can close while a human reviews it.

The same tool accepts an optional `human_input` second leg. Code Factory
validates the decision, reviewer identity, debt acknowledgements, and the
original `tool_call_id`/`proof_card_hash` bindings, then returns an `mcp2`
`completed` response containing a deterministic local receipt digest. This is
not MCP transport negotiation and is not provider approval: no session or
receipt file is retained, and no retry, merge, release, publication,
deployment, signing, credential, or connector action is performed. Provider
state remains unobserved and the human-controlled release gates remain
authoritative.

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

`factory.codex_metadata_audit` is deliberately narrower than a conversation
export. It reads only explicit workspace-relative paths (or the bounded local
defaults) and evaluates run provenance such as revision, task/intent hash,
scope, command/test receipt, stop reason, and verifier outcome. Private chat
text, credentials, raw tool output, and records outside the selected workspace
are not accepted as authority evidence. Historical state files can be reported
as unbound history, but cannot become live gate proof. See
[Oracle Firewall](ORACLE_FIREWALL.md).

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
