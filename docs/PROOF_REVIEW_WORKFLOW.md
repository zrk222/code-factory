# Proof Review Workflow

`factory proof-review` is one human-controlled front door for reviewing work from
Codex, Claude Code, GitHub Copilot, Cursor, or another JSONL-capable harness. It
does not run an agent, install vendor configuration, apply a repair, or approve
work.

## Five-minute path

1. Write a small JSON intent draft:

   ```json
   {
     "outcome": "Return the declared answer.",
     "acceptance": ["The service returns 42."],
     "rejection": ["The service returns any other value."],
     "validators": ["service-unit"],
     "allowed_paths": ["src"],
     "non_goals": ["Deploy the service."]
   }
   ```

2. Seal the named-human-confirmed contract:

   ```powershell
   factory proof-review contract --root . --id service-intent --draft intent.json --confirmed-by "Reviewer Name" --json
   ```

3. Review the exact change:

   ```powershell
   factory proof-review quick --root . --id service-change --contract .factory/proof-review/contracts/service-intent.json --changed src/service.py --json
   ```

The result is exactly one route: `evidence_required`, `human_required`,
`reverification_required`, or `review_ready`. `review_ready` means ready for a
person to review—not approved, mergeable, deployable, compliant, or
production-ready.

## Agent-neutral trajectory evidence

Run `factory proof-review hooks --root .` to write five inert, reviewable hook
templates below `.factory/proof-review/hooks/`. Code Factory does not modify
Copilot, Claude, Codex, Cursor, or other vendor settings. A team may install a
template separately after reviewing it.

Use `factory proof-review trajectory` with a bounded local trace and policy to
check required event order, tool policy, workspace scope, and a terminal audit
from an actor other than the worker. A self-audited trajectory fails closed.

## Learning, team review, and sharing

- `factory proof-review learn` converts a current causal failure into an
  immutable regression capsule only after a named human confirms it.
- `factory proof-review inbox` separates current, stale, and invalid records and
  puts `human_required` work first.
- `factory proof-review card` exports JSON, Markdown, and SVG; `card-verify`
  verifies the JSON digest offline.
- Graph Ops shows the same bounded inbox and next item as a read-only panel.

All inputs are workspace-contained and capped at 1 MiB. Trajectories are capped
at 500 events and the inbox at 500 records. Receipts contain hashes and bounded
facts—not prompts, logs, credentials, source bodies, inferred users, or claimed
time/token/productivity savings.
