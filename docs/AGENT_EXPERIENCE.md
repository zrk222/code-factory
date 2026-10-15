# Agent Experience Contract

Code Factory treats its CLI as an interface for both people and coding agents.
The front door follows a small, testable subset of the AXI agent-experience
principles without inheriting external benchmark claims.

## Contract

| Principle | Factory behavior |
|---|---|
| Content first | `factory` returns live state instead of generic help. |
| Definitive empty states | Proof categories print explicit zero counts. |
| Pre-computed aggregates | Brick compatibility and proof counts arrive in one call. |
| Contextual disclosure | One state-derived action; commands appear only when a safe command is available. |
| Structured automation | `factory home --json` and `factory doctor --json` are stable machine views. |
| Fail loud | Unknown commands and flags retain argparse exit code 2. |
| Bounded output | Home output contains counts and paths, not receipt bodies. |

Receipts remain JSON because they are durable interchange artifacts with schema
validation and hashing. Token-optimized display formats may be added only after
their parser, round-trip behavior, and measured token effect are benchmarked.

## First Call

```console
$ factory
bin: .../factory
description: Local code audit and next action
bricks: ... installed
action: Inspect evidence gaps and define this task's checks
proof:
  receipts: 0
  traces: 0
  challenges: 0
  passports: 0
next:
```

The home view complements the first-class Mermaid Factory Passport graph in
[ProofLab](PROOFLAB.md): one is the lowest-cost discovery surface; the other is
the durable visual proof artifact.

## Explicit task checks

The current source candidate adds `factory home --root . --schedule checks.json
--json`. `checks.json` must be an explicitly selected, workspace-contained
`factory.incremental-plan.v1` manifest. The command plans through the existing
incremental scheduler and does not execute a check or create workspace telemetry.
With no selected manifest, `audit_state` is `NOT_REQUESTED`; missing or invalid
inputs are `INCOMPLETE`, never a clean audit.

`daily_action` carries one `primary_action`, `RUN/REUSE/SKIP/BLOCK` proof counts,
and plan/manifest identities when available. `freshness: PLAN_INPUTS_ONLY` and
`execution: NOT_RUN` distinguish planning from execution and source coverage.
A missing command is intentional: choose the approved workflow for the task.
Do not invent a feature name or treat an action label as execution permission.
Mission Control and `factory.next_action` use the same loaded action projection;
the browser tools cannot select a schedule or start an audit.

This candidate guidance is not evidence of installation, registry publication
or a replacement of immutable public `0.48.1` packages. Required CI and versioned
distribution gates remain separate.

## Work from a Linear or Jira issue

The source candidate adds one optional ticket workflow. Configure credentials
privately in `FACTORY_LINEAR_TOKEN` (personal key by default; set
`FACTORY_LINEAR_AUTH=oauth` for an existing OAuth access token), or
`FACTORY_JIRA_EMAIL` and `FACTORY_JIRA_TOKEN` for Jira Cloud. No SDK, daemon or
background polling is required. Tokens are not saved in issue artifacts.

```console
factory issues import --provider linear --issue APP-123 --criterion "Returns expected value" --json
factory issues draft --imported .factory/issues/import-<hash>.json --contract checks.json --observations observations.json --json
factory issues publish --draft .factory/issues/draft-<hash>.json --confirmation publish:<draft-sha256> --json
```

For Jira, import with `--provider jira --site https://your-team.atlassian.net`.
Review the imported text as untrusted data; repeat `--criterion` for each
operator-reviewed acceptance requirement. The draft reuses the existing
workflow audit and maps requirements to check IDs, profiles and evidence hashes.
Its PASS means recorded evidence completeness, not semantic correctness.

Inspect the complete draft before confirming publication. CF records the exact
body, destination and candidate confirmation; this is operator intent, not
authenticated reviewer identity. Publication checks freshness, deduplicates the
comment and requires exact remote readback. Ambiguous deliveries stop for
reconciliation; more than 100 existing comments also stops safely. No issue is
closed and no repair, release or code execution is authorized by a ticket.

API-shaped fixture tests are local development evidence. Actual authenticated
provider operation, new-issue creation, background synchronization and Linear
agent-session support require separate integration evidence and remain pending.
