# External runtime evidence

Code Factory can consume a small, offline export from a runtime-test runner and
put the result beside local proof without becoming that runner's client. This
is useful for TestSprite, a CI browser runner, or an internal harness: the
runner remains responsible for execution, while Code Factory makes the result
hash-bound, comparable, and visible in Graph Ops.

## What is accepted

The input is one workspace-contained JSON object with schema
`factory.external-runtime-bundle.v1`. It contains only normalized facts:

```json
{
  "schema": "factory.external-runtime-bundle.v1",
  "provider": "testsprite",
  "project_id": "approval-tracker",
  "test_id": "checkout-approval",
  "run_id": "run-2026-08-24-001",
  "snapshot_id": "snapshot-42",
  "code_version": "commit-abc123",
  "environment": {"fingerprint": "ci-node-22", "label": "ci"},
  "verdict": "failed",
  "failure_kind": "assertion",
  "first_failed_step": {"index": 2, "label": "submit"},
  "hypothesis": "The approval transition is not persisted.",
  "recommended_fix": "Inspect the transaction boundary.",
  "artifacts": [
    {"path": "artifacts/runtime-log.txt", "sha256": "<64 lowercase hex>", "kind": "runtime-log"}
  ],
  "observed_at": "2026-08-24T12:00:00Z"
}
```

An adapter may map a provider's native export into this envelope. The
`testsprite` value is an identifier only; Code Factory never invokes TestSprite,
contacts its API, fetches credentials, or infers facts from a dashboard.

## Commands

```bash
factory external import exports/testsprite-run.json \
  --root . --provider testsprite \
  --out .factory/external-evidence/testsprite-run-2026-08-24-001.json --json

factory external diff \
  .factory/external-evidence/left.json \
  .factory/external-evidence/right.json \
  --root . --json

factory graph ops --root . --json
```

The import writes an immutable, idempotent
`factory.external-runtime-receipt.v1` receipt below
`.factory/external-evidence/`. It stores the source bundle path and SHA-256,
normalized identifiers, the declared verdict, and artifact hashes; it does not
store source code or raw provider logs. The importer rejects malformed JSON,
provider mismatches, workspace escapes, changed artifact bytes, duplicate
artifact paths, and bundles or artifacts over 1 MiB. A rejected import writes
no receipt.

The diff command verifies both receipts again. For the same provider, project,
and test with different run IDs it emits
`EXTERNAL_DIFF_COMPARABLE` and deterministic verdict, failure-kind, first-step,
code-version, environment, and artifact deltas. Different provider, project, or
test identities emit
`EXTERNAL_DIFF_INCOMPARABLE` and exit non-zero.

## Graph Ops boundary

Valid receipts appear as `external_runtime` nodes with
`observed_external` status. Hypotheses and recommended fixes remain separate
from verified facts. The node carries an all-false authority map and
`execution: false`; external evidence cannot authorize a repair, merge,
release, deployment, signing action, credential use, connector, or message.
Stale or malformed receipts are reported as source errors and never become
trusted graph facts.

When the local Graph Ops page receives these nodes, its **Observed runtime**
lane shows the provider/test identity, verdict, first failed step, environment,
run id, artifact count, hypothesis, and suggested next check. Invalid or stale
receipts are shown as fail-closed observations that must be re-imported. The
lane is explanatory only; it adds no provider request or execution control.

When a verified receipt is `failed`, `blocked`, or `unknown`, Graph Ops adds the
deterministic `review_external_runtime_failure` next action and the
`GRAPH_OPS_EXTERNAL_RUNTIME_TRIAGE_READ_ONLY` marker. This tells the developer
to review the first failed step and hypothesis before admitting a bounded local
proof or repair. It does not run the provider, apply a fix, or change any
authority. Invalid or stale receipts keep the higher-priority
`refresh_external_runtime_evidence` action so untrusted observations are
refreshed before triage.

The Graph Ops page mirrors that state in a **Review before repair** callout. It
names the next action, repeats the first-step/hypothesis review boundary, and
states that no automatic repair or external-effect control is available. The
callout is hidden when invalid or stale evidence has precedence, and it stacks
on narrow screens without adding a second endpoint or provider integration.

Each valid observation card also provides **Inspect node details**. This is a
local evidence locator: it selects the exact `external_runtime` node already
rendered in Graph lanes, focuses its existing detail panel, and scrolls it into
view. If the target is missing, the control is disabled and the UI reports
`REQ_EXT_NAV_MISSING` rather than selecting a substitute. The affordance stays
read-only, keyboard accessible, and full width on narrow screens; it never
calls a provider, mutates workspace state, authorizes execution, or infers a
repair.

## Intent trace in Graph Ops

Graph Ops also reads the newest local Forge `ship` line from each bounded
`.forge/*/receipts.jsonl` file. When the run was driven through Factoryline,
the standard `receipts/forgeline-*-ship-*.json` receipt carries an explicit
`outputs.intent_trace` adapter. The adapter binds the CLI's explicit
`intent_traceable` result to the Forge line hash without rewriting Forge's
append-only store. Graph Ops prefers that adapter for the feature and retains
the upstream line as a fallback only when no adapter exists. The **Forge
receipt · intent trace** panel shows the recorded intent hash, obligation
result, shipped state, adapter provenance status, and content hashes for both
the Factoryline receipt and the observed Forge line. A
`traceable` card means the evidence explicitly recorded `intent_traceable=true`;
it is not a new approval or a cryptographic signature.

For a hash-bound adapter, the panel also shows the normalized local Forge
receipt path and the exact 1-based ship-line number used to calculate the
observed hash. This is reviewer navigation evidence: it makes the offline
source easy to inspect without following links, mutating either receipt, or
granting any authority. Missing or invalid bindings leave the source and line
unset rather than guessing a location.

When the adapter is fully hash-bound, Graph Ops also projects a read-only
`intent_source` node for the exact Forge ship line and a
`bound_to_forge_line` edge from the intent trace to that node. The node carries
the normalized path, 1-based line, observed raw-line hash, and false authority
flags, so a reviewer can traverse the graph to the evidence without copying a
path from prose. Mismatch, missing, and invalid bindings intentionally emit no
source node or lineage edge; the card remains untraceable and the graph stays
fail closed. The edge is navigation evidence only and cannot execute, repair,
approve, publish, deploy, sign, message, access credentials, or grant a
connector.

If no ship receipt exists, the panel says intent traceability is unverified. A
missing, malformed, blocked, or untraceable receipt stays fail closed and emits
`GRAPH_OPS_INTENT_TRACE_FAIL_CLOSED`. A malformed adapter suppresses the legacy
fallback for that feature so an older traceable line cannot mask the newer
receipt-integrity failure. If the adapter's Forge-line hash or shipped,
obligation, or intent values disagree with the current bounded Forge line,
Graph Ops emits `GRAPH_OPS_INTENT_ADAPTER_MISMATCH` and keeps the card
untraceable. The projection is local and read-only: it does not
infer intent, run Forge, call a provider, mutate the workspace, or grant
execution, approval, publication, deployment, signing, messaging, credential,
or connector authority.

This is an observation bridge, not a TestSprite integration claim and not a
production-readiness claim. A human or repository-owned workflow still decides
which runner to use and what local proof is required.
