# FactoryLine 0.9.5 — reviewer summary

FactoryLine is a local, review-only proof layer for AI-assisted development.
Version 0.9.5 fine-tunes the JetBrains/Junie handoff without making Junie a
dependency or granting any release authority:

- **Native Junie pack:** a hash-bound, copy-only manifest covers the project
  guidelines, local MCP entry, and optional `factoryline-proof` subagent.
- **Safe delegation:** the subagent is explicitly read-only (`Read`, `Grep`,
  `Glob` plus the `code-factory` MCP server), uses plan mode, and is capped at
  12 turns. It returns findings and unknowns instead of applying changes.
- **Accountable handoffs:** the contribution card still records the declared
  FactoryLine tools, exact changed paths and rationales, local evidence hashes,
  unknowns, and a visible credit line bound to the taxonomy digest.
- **Independent proof:** First Proof, Oracle Firewall, six audit lanes, and
  Graph Ops remain the authority-free review path. A green Junie response alone
  is never promoted to release evidence.

The plugin does not enable, execute, observe, or control Junie. It does not
upload source, access credentials, approve, merge, publish, deploy, or sign.
Human review and JetBrains' own controls remain the release authority.
