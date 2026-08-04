# Code Factory 0.24.0

## Unified Graph Ops

Code Factory 0.24.0 adds a local, read-only Graph Ops overlay and visual
console. It links existing Product Graph, slice, mission, approval, completion,
content-addressed proof, proof-plan, trace, receipt, and artifact facts into
one deterministic result with a canonical hash and one safe next action.

Use `factory graph ops --root . --json`, open `/graph-ops` from Factory Studio,
or use the new **Unified Graph Ops** entry in VS Code and JetBrains IDEs.

For an outcome-first entrypoint, `factory mvp "..." --root .` creates one
contained local web MVP starter at `./my-mvp` with explicit proof commands. The
Studio default is now **Instant MVP**; its **Professional workflow** exposes
the same Graph Ops, mission, proof, policy, and enterprise capabilities without
changing authority boundaries.

`factory graph impact --changed <path>` adds a professional change-impact view:
it follows only explicit proof input edges and returns a stale-only rerun set,
while keeping verified-current and unmatched paths distinct.

The feature is bounded to 500 nodes, 1,000 edges, and 1 MiB per source. It
preserves partial readable results with compact errors. It neither executes
gates nor adds approval, publish, deploy, signing, messaging, credential, or
connector authority.

No time, token, cost, productivity, or conversion savings are claimed for this
release. Existing paired savings receipts remain the only source for such
measurements.
