# Spec: studio-journey
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Connect the existing guided PRD, approved mission, candidate binding, running local preview, executable checks and exact isolated repair into Studio. Reuse existing mission and repair contracts. A starter is not a verified bespoke app; evidence states govern progress.

### User roles
- Beginner operator: chooses a suggested answer or custom answer and reviews the next action.
- Coding agent: consumes the approved task packet and supplies a bound candidate.
- Reviewer: checks executed evidence and exact repair scope before promotion.

### Requirements (EARS)
- The system shall emit 4 stage records for build, preview, verification and repair after an approved guided mission, with separate executed, failed and missing-evidence states in at most 65536 bytes; the receipt shall emit `STUDIO_JOURNEY_R1` for this invariant.
- When a candidate is selected, the system shall verify the existing mission candidate binding against current source hashes and owner before every action; the receipt shall emit `STUDIO_JOURNEY_R2` for this invariant.
- If source or approval hashes change, the system shall reject the action without executing a command or displaying the previous preview as current; the receipt shall emit `STUDIO_JOURNEY_R3` for this invariant.
- When build or verification execution is requested, the system shall reject requests lacking confirmation of the exact command, candidate and digest-pinned container; otherwise emit an execution receipt after running argv without a shell in a network-disabled container, and apply a timeout of at most 120 seconds, memory of at most 512 MiB, and Docker --pids-limit=64; the receipt shall emit `STUDIO_JOURNEY_R4` for this invariant.
- The system shall retain an action receipt with candidate hashes, argv, exit code, timeout and cleanup facts, and bounded logs of at most 65536 bytes per stream; the receipt shall emit `STUDIO_JOURNEY_R5` for this invariant.
- When preview is requested, the system shall return only declared candidate preview assets from the workspace under a sandboxed iframe, without exposing arbitrary local files, Studio tokens or parent-origin access; the receipt shall emit `STUDIO_JOURNEY_R6` for this invariant.
- When repair is requested, the system shall return the result of the existing exact mission-bound repair approval and isolated executor; mission approval shall not become repair approval; the receipt shall emit `STUDIO_JOURNEY_R7` for this invariant.
- When the operator resumes, the system shall reject stale candidate and evidence bindings and return retained failed attempts rather than counting a saved stage as success; the receipt shall emit `STUDIO_JOURNEY_R8` for this invariant.
- If a required audit lane, execution result or behavioral oracle is absent, the system shall show incomplete coverage rather than a verified application verdict; the receipt shall emit `STUDIO_JOURNEY_R9` for this invariant.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: run approved build and checks
  Given an approved mission and a current candidate binding
  When the operator confirms the exact build command and pinned container
  Then execution uses a network-disabled container without a shell
  And the corresponding invariant records `STUDIO_JOURNEY_R1`
  And the corresponding invariant records `STUDIO_JOURNEY_R2`
  And the corresponding invariant records `STUDIO_JOURNEY_R3`
  And the corresponding invariant records `STUDIO_JOURNEY_R4`
  And the corresponding invariant records `STUDIO_JOURNEY_R5`
  And the corresponding invariant records `STUDIO_JOURNEY_R6`
  And the corresponding invariant records `STUDIO_JOURNEY_R7`
  And the corresponding invariant records `STUDIO_JOURNEY_R8`
  And the corresponding invariant records `STUDIO_JOURNEY_R9`
  And the receipt retains the candidate, command, exit code and cleanup facts
  And the stage response contains at most 65536 bytes

Scenario: reject stale candidate
  Given a candidate whose source hash changed
  When the operator requests build, preview or verification
  Then no command executes
  And the previous preview is not shown as current

Scenario: preserve repair authority
  Given an approved mission without an exact repair approval
  When repair is requested
  Then the request is rejected without a repair attempt
  And the operator receives the required approval step

Scenario: retain failures and incomplete coverage
  Given a check that exits unsuccessfully and a missing required lane
  When the operator refreshes the journey
  Then the failed attempt remains visible
  And no complete application verdict is emitted
```

## SHOULD — Technical/structural
- Reuse app_builder.py, Studio, product_missions.py, repair_sandbox.py and current contained process helpers.
- Existing 460 Python-file cap and pinned architecture ceilings shall remain unchanged.
- No publication, deployment, credential creation, model accuracy or frontier-equivalence authority.

## SHOULD NOT — Implementation details
- Do not synthesize successful execution, independent review or unsupported platform coverage.
- Do not run a project command from a read-only status request.
- Do not use an unpinned image or expose a preview to a non-loopback listener.
