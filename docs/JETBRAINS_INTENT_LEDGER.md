# FactoryLine Intent Ledger for JetBrains

Intent Ledger preserves one human-confirmed behavioral promise for one native
JetBrains Change List. It lets the next developer, reviewer, or AI assistant
see what the change is meant to preserve, which paths it was allowed to touch,
and which proof remains stale or absent.

## Fast path

1. Put one cohesive task in a native **Local Change List**.
2. Choose **Tools | FactoryLine | Capture Intent Ledger**.
3. Name the outcome, one non-goal, and the failure that must remain impossible.
4. Type the displayed capture phrase. FactoryLine writes a local record below
   `.factory/intent-ledgers/`.
5. Choose **Inspect Intent Ledger** before review. The Intent Ledger tab shows
   scope escape, stale proof, coverage gaps, or one next fact-derived action.

## What the states mean

| State | Meaning | Safe next step |
|---|---|---|
| `uncontracted` | No intact ledger exists for this Change List. | Capture an explicit promise; do not infer one. |
| `scope_escape` | A changed path was not in the declared scope. | Split the work or explicitly capture a new scope. |
| `stale_proof` | Existing proof inputs changed after the proof was recorded. | Run the declared proof through its normal approved workflow. |
| `coverage_incomplete` | Requirement-to-proof coverage remains incomplete. | Bind the requirement to an explicit slice, mission, and proof. |
| `ready_for_human_review` | No declared local gap was found. | Have a named human review the packet. |

## Boundaries

The ledger is local and evidence-first. Inspection never runs tests, edits code,
changes a JetBrains Change List, recalls memory bodies, starts an agent,
approves a change, merges, publishes, deploys, signs, accesses credentials, or
contacts a service. A `ready_for_human_review` result is not a release decision
or a guarantee that a defect cannot exist.

The built-in MCP tool is read-only, so any coding assistant can request the
same narrow current contract and next proof without receiving a full history or
an authority grant.
