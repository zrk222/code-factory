# Code Factory 0.43.0 — Evidence Supply Line

Agent governance is only useful when normal coding sessions generate reliable
evidence. This release adds a direct path from an admitted local agent run to
the existing Agent License, Combine, and Gauntlet surfaces.

## What changed

- `factory wrap` works with any argv-based local coding agent. It verifies the
  existing admission boundary before execution, captures the exact file delta,
  runs explicit independent validators, and records immutable governed evidence.
- `factory gauntlet draft` proposes inert promise drafts from real CLI
  entrypoints and inventories routes/tests without inventing HTTP commands.
- A package-level registry supplies DRAFT promise templates for all seven
  built-in target kinds without modifying their signed pack payloads.
- An optional Claude Code plugin hash-chains bounded `PreToolUse` and `Stop`
  metadata without retaining prompts, tool arguments, outputs, or credentials.

## Why it matters

Vibe coders get a shorter path from “the agent finished” to “here is what
changed and whether the declared checks passed.” Teams get a consistent,
reviewable evidence feed for earned autonomy and agent comparisons without
depending on one agent vendor.

## Boundary

The recorder observes a process; it does not sandbox it, authenticate an
external identity, enforce network policy, approve code, repair code, merge,
publish, or deploy. DRAFT Gauntlet artifacts cannot execute until a human
promotes them and grants the existing named, expiring admission.
