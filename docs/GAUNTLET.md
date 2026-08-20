# Gauntlet: Proof of Survival

The Gauntlet asks a narrower question than “does the application work?”:

> Can this declared behavior survive the specific failure cases its owner chose?

It turns a small, human-written set of promises and sabotage cases into a
**Survival Card**. A card makes every declared case visible as `survived`,
`hollow`, or `blocked`, and lists the promises that remain unproven.

The point is not to add another AI reviewer. The deciding evidence comes from
the existing positive/negative E2E proof gate: a negative check that exits zero
is visible as `HOLLOW_E2E_TEST`, not called a success.

## The boundary

Gauntlet is deliberately supervised.

- A promise owner writes the local E2E manifests; Gauntlet never generates an
  `argv` command from prose.
- `plan` reads and hash-binds the source, Reality Check, and E2E manifests. It
  does not execute a command.
- `admit` requires a named reviewer, rationale, exact confirmation phrase, and
  a 1–60 minute expiry. It does not execute a command.
- `run` executes only the already declared local E2E pairs after one current
  admission. An admission is consumed after its one allowed run.
- `status`, Graph Ops, and MCP are read-only. They cannot admit, rerun,
  repair, merge, publish, deploy, message, or access credentials.

The resulting Survival Card is integrity-verifiable offline. It is not a
production-readiness, security, coverage, performance, cost, token-savings,
quality, or release certificate. An optional Receipt v2 DSSE envelope can bind
the exact card hash when an organization supplies its own signing key and trust
root.

### Optional precision context

A source may additionally bind selected **already verified** Factory
Continuity records. This adds context provenance to the proposal and Survival
Card without turning memory into a decision-maker. The compiler reads the
existing local ledger through its read-only API, requires exact tenant, purpose,
scope, and unexpired record matches, and records only hashes, record types, and
evidence digests. It never copies a memory reference, summary, body, embedding,
or conversation into a Gauntlet artifact.

If that metadata expires, loses its independent promotion, or no longer matches
the requested scope, proposal verification fails closed. A continuity binding
does not generate a test, authorize a run, or prove the behavior; the declared
E2E pair and named one-run admission remain the authority.

## Use it

Create a workspace-contained `factory.gauntlet-source.v1` JSON file. Each
promise points to an approved Reality Check manifest and each sabotage case
points to an approved `factory.e2e_proof_manifest.v1` file:

```json
{
  "schema": "factory.gauntlet-source.v1",
  "id": "approval-gauntlet",
  "promises": [
    {
      "id": "approval-authorization",
      "statement": "Only a manager can approve a request.",
      "reality_manifest": "approval.reality.json",
      "sabotage_cases": [
        {
          "id": "wrong-role",
          "risk_tag": "authorization",
          "summary": "A non-manager approval must be rejected.",
          "e2e_manifest": "approval.e2e.json"
        }
      ]
    }
  ]
}
```

To bind previously reviewed context, add this optional `continuity` object to
the source. The record IDs are local selection inputs; the compiled proposal
and card expose only their hashes and redacted evidence metadata:

```json
{
  "continuity": {
    "db": ".factory/continuity.sqlite3",
    "tenant_id": "engineering",
    "purpose_ref": "delivery-review@1",
    "scope_ref": "repo:sha256:your-workspace-scope",
    "principal": {
      "subject": "reviewer",
      "roles": ["reader"],
      "purposes": ["delivery-review@1"]
    },
    "record_ids": ["approved-context"]
  }
}
```

Compile the inspectable proposal, review its exact command pairs, and make the
one-run admission explicit:

```powershell
factory gauntlet plan --root . --source gauntlet.json --json
factory gauntlet admit .factory/gauntlets/approval-gauntlet/<proposal>.proposal.json `
  --root . `
  --approved-by "reviewer-name" `
  --rationale "Run the declared local authorization proof." `
  --confirmation "ADMIT approval-gauntlet" `
  --json
factory gauntlet run .factory/gauntlets/approval-gauntlet/<proposal>.proposal.json `
  --root . `
  --admission .factory/gauntlets/approval-gauntlet/<admission>.admission.json `
  --json
```

The run writes canonical JSON plus Markdown and SVG card views below
`.factory/gauntlets/<source-id>/`. Verify a saved card without rerunning its
commands:

```powershell
factory gauntlet card verify .factory/gauntlets/approval-gauntlet/<card>.card.json --json
factory gauntlet card challenge .factory/gauntlets/approval-gauntlet/<card>.card.json --json
factory gauntlet status --root . --source-id approval-gauntlet --json
```

`challenge` changes an in-memory summary only and proves that the card verifier
rejects it; it never edits the original card. `card seal` is optional and
requires a caller-supplied private key, identity, issuer, tenant id, and output
path.

## Taxonomy

Each case declares exactly one purposefully simple failure shape:

| Tag | The declared failure shape |
| --- | --- |
| `boundary` | Outside the declared boundary |
| `authorization` | Missing or wrong authority |
| `idempotency` | Duplicate effect or request |
| `temporal` | Reordered or delayed event |
| `state` | Stale or conflicting state |
| `validation` | Invalid or missing input |

This taxonomy is an organizer, not a claim that every application failure is
covered. Add a case only when its E2E manifest and failure meaning have been
reviewed by the people responsible for the behavior.

## Read it where you work

Graph Ops projects valid local Survival Cards into the `gauntlet` lane and
recommends a hollow-case repair or blocked-run resolution without executing
either. MCP exposes `factory.gauntlet_status` for the same local, read-only
facts. See [AI client connections](AI_CLIENTS.md) for the local stdio boundary
and [Reality Check](REALITY_CHECK.md) for the behavior-level manifest that a
Gauntlet promise binds.
