# AGUI and MCP2 review surface

Code Factory exposes a small, controlled AGUI-style event adapter so Mission
Control, JetBrains, VS Code, and browser surfaces can render the same evidence
without learning a private vocabulary or receiving execution authority.

## The user-visible loop

An agent or developer starts with the local First Lap. Code Factory reads the
sealed mission and its file-integrity receipt, then emits four deterministic
events:

`RUN_STARTED → STATE_SNAPSHOT → REVIEW_CARD → RUN_FINISHED`

`STATE_SNAPSHOT` carries only bounded status, stale paths, next actions, and
claim boundaries. `REVIEW_CARD` is a declarative component hint; clients map it
to their own catalog rather than executing generated UI. The result is easy to
scan for a solo developer and still auditable for a team.

When the existing MCP2 release gate returns `input_required`, the adapter can
map it to an `INTERRUPT` event containing the failed lanes, proof debt, and the
human decision schema. A completed MCP2 response maps to a bounded
`RUN_FINISHED` event. In both cases, the event explicitly preserves
`humanOwned: true` and all release/execution authority remains false.

## CLI and MCP entry points

```text
factory agui review-events --root . --json
```

The local MCP server exposes the read-only `factory.agui_review_events` tool.
The progressive WebMCP manifest advertises the same capability for a loaded
browser surface. Both paths read existing local evidence; neither runs tests,
calls an agent, uploads media, contacts a provider, or approves a release.

## Deterministic safety contract

Every event uses `factory.agui.events.v1`, a contiguous sequence, a stable
event ID, and a SHA-256 payload binding. Streams are bounded to 32 events and
32 KiB per encoded event. Sensitive keys such as credentials, tokens, raw
prompts, and transcripts are rejected rather than redacted after the fact.
Streams must start with `RUN_STARTED` and end with `RUN_FINISHED`; malformed,
tampered, reordered, or over-sized events fail closed.

This is deliberately a controlled/declarative review bridge, not a claim that
Code Factory implements every external AGUI event or a full MCP2 Streamable
HTTP server. The current transport remains local stdio plus the existing
stateless JSON-RPC adapter. A future HTTP transport can reuse these events only
after its own protocol and security gates are proven.

## Value for AppForge and connected agents

AppForge's six mobile evidence categories (visual media, privacy-to-listing,
release chain, design system, production signals, and Android parity) appear as
the same review-card pattern. Agents get a compact next action instead of a
136-rule context dump; humans get a clear interrupt when a decision is theirs.
The result is less polling and fewer “green but hollow” handoffs while keeping
the source → obligation → forbidden behavior → gate → test → evidence chain
inspectable.

