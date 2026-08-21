# Engineering Judgment Safety Case

Engineering Judgment prevents a repository from repeatedly rediscovering the
same design decision—or silently violating it when a later AI-assisted diff
lands. It is a deterministic, local-first coordination layer. It does not use
a model, inspect source semantics, execute tests, edit a change, or approve a
release.

## The unit of record: a Judgment Capsule

A Capsule is a repository-tracked JSON record in `judgment/capsules.json` with:

- a stable ID, title, short summary, and explicit project-contained path scope;
- a named owner and fixed review date;
- rationale and evidence references supplied by the proposing human; and
- declared proof obligations that can later be bound to exact file hashes.

The lifecycle is deliberately narrow:

1. `factory judgment propose` writes a **proposed** Capsule.
2. A different named human runs `factory judgment promote` with a reason.
3. A promoted Capsule becomes **active**. Reconsideration records a successor
   proposal but does not weaken, hide, or waive the active decision.

There is no model promotion, anonymous override, background learning, or
implicit conversion from an existing receipt into a decision.

## Change Safety Case

Pass explicit changed paths and optional, independently produced proof receipts:

```powershell
factory judgment safety-case --root . `
  --changed src/payments/checkout.py `
  --proof-receipt .factory/proofs/checkout-contract.json --json
```

The compiler returns a read-only route:

| Route | Deterministic meaning | It does **not** mean |
| --- | --- | --- |
| `BLACK` | The Capsule store is invalid; no older or inferred decision was substituted. | That a change is dangerous or rejected. |
| `RED` | An active Capsule matched but a declared receipt is missing, invalid, unbound, or hash-mismatched. | That FactoryLine ran a test or knows how to repair it. |
| `AMBER` | Matching active obligations have exact, verified bindings; the named owner review remains required. | Approval, production readiness, merge, or release permission. |
| `GREEN` | No active tracked Capsule matched the supplied paths. | Safety, approval, or absence of risk. |

Each accepted receipt carries `factory.judgment.proof-receipt.v1`, a Capsule ID,
obligation ID, `verified` verdict, and SHA-256 bindings for the exact evidence
files. Changing a bound file makes that receipt unusable for the Safety Case.

## Surfaces

- CLI: `factory judgment propose`, `promote`, `reconsider`, `status`, and
  `safety-case`.
- MCP: read-only `factory.judgment_status` and
  `factory.judgment_safety_case` tools.
- Graph Ops: Capsule/scope nodes, review-due counts, decision-specific next
  actions, and a locked visual supervision panel.
- JetBrains: **Engineering Judgment** tab with separate, workspace-confirmed
  local actions to inspect decision status or compile a Safety Case from one
  selected native Change List.

## Authority boundary

Engineering Judgment cannot infer a decision from source, a model response, a
Slack or Notion message, a test result, or a policy document. It cannot promote
or waive a decision through Graph Ops, MCP, or JetBrains. It cannot run tests,
repair code, modify VCS, merge, publish, deploy, sign, send messages, access
credentials, or control external connectors. Humans retain each of those
decisions.
