# Spec: evidence-supply-line-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Connect ordinary local coding-agent sessions to the existing Code Factory
admission, attribution, Agent License, Combine, and Gauntlet evidence surfaces.
The feature must shorten time-to-first-receipt without inventing tests, copying
prompts, or misrepresenting observation as sandboxing.

### User roles

- Individual developer supervising a local coding agent.
- Team reviewer requiring reproducible validator evidence.
- Platform owner drafting first proof promises from repository structure.

### Requirements (EARS)

- When a user wraps an argv-based agent command, the system shall return `OBSERVED_SESSION_RECORDED` only after the supplied admission verifies `READY` and an admitted `max_wall_seconds` limit from 1 through 3600 seconds is applied. [REQ-ESL-ADMISSION]
- When a wrapped command finishes, the recorder shall emit created, modified, and deleted paths with file hashes and shall emit `scope_escape` for every path outside admitted scope. [REQ-ESL-DELTA]
- When agent execution ends, the recorder shall emit `wrong_output` for any failed explicit validator and shall not emit `hollow_test` without sabotage evidence. [REQ-ESL-VALIDATION]
- When receipts are written for a workspace of at most 10000 files, the recorder shall emit `NO_RAW_CONTENT_RETAINED` with command/output hashes, byte counts, exit facts, durations, and file hashes while rejecting retention of prompts, raw argv, raw output, credentials, and environment values. [REQ-ESL-PRIVACY]
- When a session completes, the recorder shall emit hash-bound result, verification, session, and immutable `factory.agent-run.v1` evidence for Agent License and Combine. [REQ-ESL-LEDGER]
- When `factory gauntlet draft` runs, the drafter shall return `GAUNTLET_DRAFT_CREATED` with actual project scripts, literal Python HTTP routes, test paths, and target-pack entrypoint shapes without command execution. [REQ-ESL-DRAFT]
- When an exact HTTP positive/sabotage argv pair is absent from repository structure, the drafter shall emit `HTTP_COMMAND_WITHHELD` with the route, an unresolved reason, and zero runnable manifests for that route. [REQ-ESL-WITHHOLD]
- When a promise or E2E candidate is generated, the drafter shall emit `GAUNTLET_DRAFT_INERT` with status `DRAFT`, zero execution authority, and exactly 4 promotion requirements and shall reject the artifact from executable Gauntlet schemas. [REQ-ESL-INERT]
- When enabled, the optional Claude Code plugin shall store 1 hash-linked event per matching `PreToolUse` or `Stop` invocation without tool arguments and shall return 1 scope statement that the trace is not a governed run receipt. [REQ-ESL-HOOK]
- When authority is displayed, each recorder surface shall emit 1 exact scope statement `observed execution is not sandboxed execution` and shall grant zero sandbox, network-enforcement, identity-proof, approval, repair, merge, publication, deployment, signing, messaging, or credential authority. [REQ-ESL-BOUNDARY]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Record an admitted agent session
  Given a READY packet with a declared agent, scope, and wall-time budget
  And an independent validator manifest that existed before admission
  When the agent creates one in-scope file and every validator passes
  Then OBSERVED_SESSION_RECORDED is emitted
  And the exact created path and file hash are bound
  And `scope_escape` is emitted for every changed path outside admitted scope
  And `factory.agent-run.v1` is recorded
  And `NO_RAW_CONTENT_RETAINED` is emitted

Scenario: Classify a failed validator conservatively
  Given an admitted agent command exits zero
  When one declared validator exits non-zero
  Then the session fails with `wrong_output`
  And it does not claim `hollow_test` without sabotage evidence

Scenario: Draft without inventing HTTP execution
  Given a project with one declared command-line entrypoint and one literal HTTP route
  When `factory gauntlet draft` performs static inspection
  Then `GAUNTLET_DRAFT_CREATED` is emitted
  And `GAUNTLET_DRAFT_INERT` is emitted
  And the HTTP route emits `HTTP_COMMAND_WITHHELD`
  And runnable_manifest_count is zero
  And no command is executed or approved

Scenario: Preserve hook privacy
  Given a Claude Code PreToolUse envelope containing a secret tool argument
  When the optional hook records the boundary
  Then the secret is absent from the stored event
  And the event contains a tool-input hash and previous-event hash
  And the trace says it is observational rather than governed evidence
  And the recorder says `observed execution is not sandboxed execution`
```

## SHOULD - Technical and structural

- Keep the generic recorder in `factoryline/session_recorder.py` and static
  drafting in `factoryline/gauntlet_draft.py`.
- Use the existing frozen `FailureClass` taxonomy and Agent License ledger.
- Add an inert promise template to each built-in target pack.
- Expose primary command paths for wrapping sessions and drafting promises.

## SHOULD NOT - Implementation details

- Do not invoke a shell, network client, repair, merge, publication, deployment,
  connector, credential, approval, or signing action.
- Do not infer an HTTP harness command from prose or a route decorator.
- Do not treat a hook envelope as proof that the process was contained.

## Claim and evidence boundary

- The wrapper proves only the admitted local command facts and declared
  validator results captured in its receipts.
- Declared agent/verifier subjects are identifiers, not external identity proof.
- DRAFT promises are review material, not executable tests or readiness claims.
