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
factory efficiency select --manifest .factory/context-selection.json --root . --json
factory efficiency record --manifest .factory/context-pair.json --root . --json
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

`select` accepts a bounded list of explicit candidates with declared evidence
roles. It ranks candidates against task terms and changed paths, records hashes
and omission reasons, and can require paths or roles. The score and rationale
are unverified heuristics; source verification establishes integrity, not that
the ranking is optimal. Python sources add bounded
AST summaries (definitions and line ranges, imports, calls, identifiers, and
shared-identifier references to other candidates). These are syntactic evidence
only, not a resolved call graph or runtime proof. The selection score and
rationale are heuristic metadata and are explicitly marked unverified. AST
parsing is limited to Python source files no larger than 64 KiB, with a 20,000
visited-node and 2,048-identifier/import/call collection bound; larger Python
files are marked `PARSE_LIMIT`. Other file types are marked `NOT_PARSED`.
Selection reuses its one stable source snapshot to build the
packet; `verify` rereads candidates to check freshness. Recognizable credential
files and key shapes remain digest-only; screening is best-effort, not complete
secret discovery.

`record` evaluates operator-supplied paired observations without running a
model. Both arms bind the same task, revision, model, tools, budget, and quality
rubric. Elapsed time includes context gathering, coding, and repair; at least
three pairs are required before evaluating the 50% elapsed-time reduction
target (two times throughput). Cost and token deltas are absolute USD and
tokens when recorded. Observations are unverified, and the target is not a
global performance claim. Status marks cached evidence unverified and makes no
provider-usage, freshness, or production-savings claim.
