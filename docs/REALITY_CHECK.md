# Factory Reality Check

Factory Reality Check binds one plain-language product behavior to a
human-approved local proof-by-sabotage run. Its Intent Contract Inspector first
requires explicit positive and negative assertions so the runner cannot quietly
test only the happy path.

It covers the gap between “the AI built it” and “the app behaved as promised.”
It does not invent test commands or browser actions. You declare a happy path
and a failure case, then reference an approved E2E argv pair.

```powershell
factory reality verify --root . --manifest approval.reality.json --out-dir .factory/reality --json
factory reality inspect --root . --manifest approval.reality.json --json
```

## Contract

```json
{
  "schema": "factory.reality-check-manifest.v1",
  "id": "approval-flow",
  "approval": { "state": "approved", "approved_by": "named-reviewer" },
  "behavior": {
    "promise": "A manager can approve a request.",
    "happy_path": "An approved request is recorded.",
    "failure_case": "A non-manager cannot approve."
  },
  "intent_assertions": [
    { "id": "manager-can-approve", "statement": "Manager approval is recorded.", "evidence": "positive" },
    { "id": "non-manager-blocked", "statement": "Non-manager approval is rejected.", "evidence": "negative" }
  ],
  "e2e_manifest": "approval.e2e.json"
}
```

The referenced E2E manifest provides explicit positive and negative argv
arrays, working directory, timeout, artifact paths, and a separate approval.
`factory reality inspect` is read-only: it rejects missing, duplicate, or
one-sided assertions before a command is eligible to run. A completed Reality
Check binds every assertion to the corresponding verified or unverified E2E
outcome.

## Result states

- `REALITY_CHECK_VERIFIED`: declared positive exits zero, negative exits
  non-zero, and required artifacts exist.
- `REALITY_CHECK_HOLLOW`: declared negative exits zero.
- `REALITY_CHECK_BLOCKED`: another local command, artifact, or timeout gate
  did not pass.

The receipt contains the behavior contract, public E2E receipt, Mermaid map,
and Markdown summary. Save it under `.factory/reality/` to show a typed
`reality_check` node in Graph Ops.

## Guided human authorization

Graph Ops starts as read-only. Select a verified `reality_check` node, enter a
named approver and reason, and confirm the one-hour authorization. Studio then
writes a local `factory.graph-ops-authorization.v1` receipt that binds the
selected proof-card bytes, behavior-manifest bytes, approver, reason, action,
and expiry. A second confirmation can consume that authorization to rerun the
same local E2E pair once.

This is deliberately progressive:

- **New users** see one plain-language eligible action and a confirmation.
- **Teams** get a named approver, rationale, expiry, one-use consumption, and
  a graph-visible authorization record.
- **Enterprises** can inspect the source paths, SHA-256 bindings, action scope,
  and authority fields in the same typed Graph Ops nodes.

The authorization never applies a repair. For a verified ProofSearch winner,
Graph Ops can instead record a `repair_plan_review` handoff for a separately
approved repair runner; source mutation, merge, publish, deployment, signing,
messaging, credentials, and connectors remain denied.

## Boundary

Reality Check executes only caller-approved local argv arrays with `shell=False`.
It does not generate tests, provide browser/host isolation, enforce egress,
repair source, merge, publish, deploy, sign, send messages, access credentials,
or grant connectors. A verified card is not production readiness evidence.
