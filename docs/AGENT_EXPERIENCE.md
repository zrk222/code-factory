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

## Connect your own Linear workspace

The source candidate uses a public Code Factory OAuth application, so every CF
user can authorize their own workspace. No owner account or shared API token is
required. Install CF with the `issues` extra to enable secure OS-vault storage.

```console
factory issues connect --connection work
factory issues status --connection work --json
factory issues import --connection work --provider linear --issue APP-123 --criterion "Returns expected value" --json
factory issues draft --imported .factory/issues/import-<hash>.json --contract checks.json --observations observations.json --json
factory issues publish --connection work --draft .factory/issues/draft-<hash>.json --confirmation publish:<draft-sha256> --json
factory issues disconnect --connection work
```

Connect opens Linear's own consent screen using PKCE S256. Each connection pins
the consenting user and workspace; tokens stay in that local user's secure OS
credential vault. Only read and comment creation are requested. No client secret
is embedded. Named connections permit separate workspaces without sharing
credentials; refresh preserves identity pins and disconnect confirms revocation.
The fixed loopback callback closes after completion or timeout.

Review imported ticket text as untrusted data; repeat `--criterion` for each
operator-reviewed requirement. The local draft reuses the existing workflow audit
and maps requirements to check IDs, profiles and evidence hashes. Its PASS means
recorded evidence completeness, not semantic correctness. Inspect the exact draft
before confirming. Publication rechecks freshness, deduplicates and requires
remote readback. Uncertain writes and more than 100 comments stop safely.

Jira Cloud and automation may use explicit `--expert-token` mode with private
`FACTORY_JIRA_EMAIL`/`FACTORY_JIRA_TOKEN` or `FACTORY_LINEAR_TOKEN`. Jira import
also requires `--site https://your-team.atlassian.net`. An existing Linear OAuth
access token uses `FACTORY_LINEAR_AUTH=oauth`. No issue is automatically closed;
a ticket never authorizes code execution, repair or release.

The public OAuth app is registered. Live Windows consent, OS-vault storage,
refresh rotation, identity verification and issue import have been exercised in
one workspace. A separate customer workspace and live comment publication remain
unverified; fixture tests do not prove those flows.
New-issue creation, background synchronization and Linear agent sessions remain
follow-on work. A user's ChatGPT Linear connection is separate from CF's product
authorization and is not distributed to other users.

## Assembly process evidence (source candidate)

Assembly records an unsuccessful enrollment receipt before each CLI attempt,
then updates that same attempt with bounded exit, cleanup and stream facts.
Output evidence hashes and counts the captured bytes; it does not copy raw
streams into the action record. Repeated attempts have distinct receipt IDs
and retain the shared Assembly run identity. Atomic replacement preserves the
prior receipt if a final write fails; power-loss durability is not claimed.
Process completion does not prove correct task output, provider/model identity,
validated token usage or release readiness. The existing audit and review gates
still apply. Missing process observations remain incomplete.
