# Intake Parameter Envelope

The Intake Grill answers *what outcome is intended*. The Intake Parameter
Envelope answers *how bounded work may be reviewed*. It keeps a worker from
silently widening scope, budgets, risk, external effects, or the audit set.

## Start here

```powershell
factory intake parameters seal intake-request.json --root . --json
factory intake parameters verify .factory/intake-parameters/<project>/<request-sha>.json --root . --json
factory intake parameters status --root . --json
```

The request must bind to a verified `factory.intake-confirmation.v1` receipt and
must contain exactly these groups:

- `mode`: `human_controlled`, `supervised`, or `autonomous`.
- `risk`: `low`, `medium`, `high`, or `critical`.
- `budgets`: bounded mission maxima for iterations, wall time, tokens, and cost.
- `scope_paths`: one to 64 safe workspace-relative paths.
- `required_lanes`: all six runtime-audit lanes, in canonical order.
- `external_effects`: the same `local_only` or `human_controlled` decision as
  the named human intake confirmation.

Each group has an explicit provenance origin: `human_confirmed`,
`trusted_source`, `observed_production`, or `agent_proposed`. Only the first two
are authoritative. Observed or agent-proposed values produce
`REVIEW_REQUIRED`; they are visible guidance and cannot block or release work.
Autonomous mode is refused unless effects are local-only and every parameter
group is authoritative. Envelopes expire within 30 days and are rechecked on
every verification.

## What the receipt proves

The receipt is content-addressed and binds the request hash, confirmation hash,
normalized parameters, provenance, expiry, and the zero-authority boundary.
Tampering, request/confirmation drift, expired values, traversal, symlinks,
secret-shaped values, incomplete six-lane coverage, and budget widening fail
closed. `READY` means the envelope is internally verified and authoritative; it
does not mean code ran or that a release is approved.

Mission Control, Graph Ops, stdio MCP, WebMCP, and the Junie taxonomy expose
bounded status. Their action summaries tell a human exactly whether to repair an
invalid envelope or review advisory values. No surface executes a worker,
changes intent, grants credentials, or performs provider actions.

## Canonical proof chain

`human intake confirmation → parameter envelope → six audit lanes → evidence → human decision`

The envelope is a control-plane input, not a replacement for the independent
runtime validators or the human approval boundary.
