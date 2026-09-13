# FactoryLine 0.9.4 — reviewer summary

FactoryLine is a local, review-only proof layer for AI-assisted development.
The 0.9.4 adapter keeps the senior-engineering controls from 0.9.3 and adds a
proof-coupled handoff for Junie and other coding agents without granting the
IDE or agent release authority:

- **Accountable handoffs:** the contribution card records the known tool,
  exact changed paths, per-file rationale, workspace-local hashes, explicit
  unknowns, and a visible credit line. The taxonomy digest prevents a card
  from silently changing the recognized tool inventory.
- **Junie-native reviewer path:** the project pack exposes a hash-bound,
  copy-only manifest plus an optional `factoryline-proof` Markdown subagent.
  Its allowlist is limited to `Read`, `Grep`, `Glob`, and the `code-factory`
  MCP server, so Junie can delegate evidence review without granting that
  reviewer edit, shell, web, or release authority.
- **Independent proof:** First Proof, Oracle Firewall, six audit lanes, and
  Graph Ops keep the request, forbidden behavior, test, evidence, and next
  human decision together. A green agent message alone is not promoted.
- **Evidence quality:** signed execution attestations, real-defect benchmark
  metrics, dependency-aware incremental routing, and fresh repair comparisons
  remain bounded, content-addressed, and review-only.
- **Optional Junie relationship:** Junie can plan or implement; FactoryLine
  checks the supplied handoff beside Qodana, Copilot, CodeRabbit, Devin, or a
  generic client. Junie is not required, controlled, or endorsed by the
  plugin.

Every result is bounded JSON with a digest and `authority: none`; adapters do
not access credentials, upload source, publish, deploy, merge, or approve
releases. The human reviewer retains the final decision.
