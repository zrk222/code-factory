# Spec: openvsx-cadence-exception
Status: draft
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Publish the VS Code adapter 1.1.1 to Open VSX from an exact, reviewed main commit, using the maintainer's explicitly approved one-time cadence exception. Keep the normal seven-day rule in force for every other release.

### User roles
- Publisher: requests the protected Open VSX workflow and supplies the exception reason.
- Release approver: authorizes the protected `openvsx` deployment environment.
- Reviewer: verifies the exact source changes and required CI checks before merge.

### Requirements (EARS)
- The system shall accept a cadence exception envelope only when the channel, semantic version, candidate tag, source commit, requesting actor, and issue and expiry timestamps match the candidate and fall within a one-hour validity window.
- When a cadence exception is used, the system shall preserve the failed normal cadence observation and record the exception as a distinct, hash-bound check in the preflight receipt.
- If the publication is not explicitly enabled or the protected deployment environment has not authorized the run, the system shall not apply the exception or access the Open VSX credential.
- If any source, architecture, artifact, metadata, or CI check fails, the system shall block publication even when the cadence exception is valid.
- When a candidate has no matching cadence exception, preflight shall reject release if fewer than seven days have passed since the previous release for the same channel or if four or more releases for the same channel fall within the previous 30 days.
- The system shall package VSX version 1.1.1 from the reviewed merged source and publish only through the protected Open VSX workflow.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: exact one-time cadence exception
  Given a source-bound 1.1.1 candidate and explicit, unexpired exception for the same VSX tag and commit
  And the protected Open VSX publication environment has authorized the run
  When all non-cadence release checks pass
  Then preflight records the failed normal cadence and a separate valid exception
  And publication may proceed through the protected workflow

Scenario: exception cannot hide other failures
  Given a valid cadence exception
  When source binding, architecture, artifact identity, or required CI evidence fails
  Then preflight blocks publication

Scenario: normal cadence remains enforced
  Given no exception matching the exact candidate
  When the seven-day cooldown or rolling release limit is active
  Then preflight blocks publication and reports the next eligible time
```

## SHOULD — Technical/structural
- ADR references: none; extend the existing release-candidate contract and Open VSX workflow.
- Data model: a small exception envelope bound to channel, version, tag, source commit, actor, reason, issue/expiry times, and protected workflow run.
- API contract: `factory release preflight --cadence-exception .factory/release-cadence-exception.json`; Open VSX dispatch may supply an exception reason only when `publish=true`.
- Decision facts: `cadence_admitted`, `exception_matches`, `exception_unexpired`, `publish_enabled`, `all_other_gates_pass`.

## SHOULD NOT — Implementation details
- Never change or relax the configured cadence, rewrite an existing tag, or accept an unbound/free-form override.
- Never claim the local preflight itself authenticates the GitHub deployment approver.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | `cadence_admitted=true` | Continue with all existing gates unchanged. |
| 2 | `cadence_admitted=false`, `exception_matches=true`, `exception_unexpired=true`, `publish_enabled=true` | Record the normal failure and exception separately; continue only if `all_other_gates_pass=true`. |
| 3 | `exception_matches=false` or `exception_unexpired=false` or `publish_enabled=false` | Preserve the normal cadence block. |
| 4 | `all_other_gates_pass=false` | Block regardless of the exception. |
