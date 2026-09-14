# Context Efficiency

Code Factory can assemble a small, repeatable hand-off for an agent without
making the agent reread a whole repository. `factory efficiency pack` accepts a
sealed request manifest and produces a `factory.context-efficiency-packet.v1`
artifact containing:

- the mission and immutable contract digest;
- changed paths and a deterministic priority/role order;
- bounded excerpts (head and tail when truncation is required), or digest-only
  rows for binary and secret-shaped material;
- source identity and SHA-256 hashes so drift is visible before hand-off; and
- an exact cache key for reusing the same request/source observation.

Cache reuse avoids repeating packet assembly and context serialization for an
unchanged observation. The builder still rechecks bounded source identities and
digests before reuse; this is intentional evidence work, not an unsafe stat-only
shortcut.

The packet is deliberately read-only. It does not execute a source, call a
provider, alter intent, approve a gate, or publish a release. Four UTF-8 bytes
per token is used only to estimate a budget; it is not a provider usage or
savings measurement.

## CLI

```powershell
factory efficiency pack --manifest .factory/context-request.json --root . --json
factory efficiency verify .factory/context-efficiency/<key>.json --root . --json
factory efficiency status --root . --json
```

The request manifest has exactly `schema`, `mission_id`, `contract_digest`,
`changed_paths`, `sources`, `max_tokens`, and `per_file_tokens`. Budgets are
bounded to 256..12,000 total tokens and 32..2,000 tokens per file. Source and
changed-path lists are capped at 128 entries, and each source is read with a
stable before/after filesystem identity check. Unknown fields, traversal,
symlinks, secret-shaped request fields, or source drift fail closed.

Mission Control, Graph Ops, stdio MCP, and progressive WebMCP expose only the
packet/cache status. A `BLOCKED` cache is a review cue to rebuild from the
sealed request; `MISSING` is not a release failure. The feature preserves the
existing seven-reader Mission Control performance baseline.
