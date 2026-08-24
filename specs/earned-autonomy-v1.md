# Spec: earned-autonomy-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST — Functional core

### Description

Give a declared coding-agent identity a local, per-repository autonomy license
only from current, admission-packeted, independently verified run evidence. A
license is derived deterministically, expires without new evidence, caps the
autonomy declared by a Loop Passport, and is demoted immediately after a severe
failure. `factory combine` compares two or more completed, sealed task runs
without treating a vendor score, elapsed time, or agent-authored claim as proof.

### User roles

- **Harness operator:** creates a normal Loop Passport and an admission packet.
- **Agent operator:** supplies a *declared* agent identity and a bounded run
  result; this is not external identity authentication.
- **Independent verifier:** supplies a bounded verification receipt and a
  declared verifier identity different from the agent subject.
- **Reviewer:** reads or optionally DSSE-seals a license or Combine scoreboard;
  no read surface starts work, repairs code, or releases anything.

### Requirements (EARS)

- When `factory license record` receives a current `factory.run-admission.packet.v1`, a declared `factory.agent-identity.v1`, a workspace-contained result receipt, and a declared independent verifier identity, the system shall emit an immutable `factory.agent-run.v1` ledger event bound to the admission packet and receipt hashes.
- If the admission packet is not `READY`, the result receipt is absent or hash-mismatched, the identity differs from the packet identity, or the verifier subject equals the agent subject, then the system shall reject the event without writing a license record.
- When a declared agent has at least twenty current clean governed events, at least fifteen current independent verification receipts, current evidence within thirty days, and a non-empty common permitted path scope, the system shall issue an `autonomous` local license for that scope.
- While an agent has less evidence than the autonomous policy requires, the system shall issue no more than `supervised` authority; a first governed event may remain `human_controlled` until the supervised policy is met.
- If a governed event contains `hollow_test`, `hollow_validator`, or `scope_escape`, then the system shall write an incident capsule and immediately derive a `human_controlled` license. It shall require five clean governed events after the latest incident before it may return to `supervised`.
- When the latest governed evidence is older than thirty days, the system shall decay a formerly autonomous license to `supervised`, never preserve autonomous permission from stale evidence.
- When a new admission request declares an agent identity, `run_admission.prepare_admission` shall reject a requested Loop Passport autonomy level or path scope above the current license with code `E_LICENSE_EXCEEDED`.
- When `factory combine plan` seals a task for two through eight declared agents, and `factory combine score` receives one matching immutable governed run event per declared agent, the system shall emit a canonical `factory.combine-scoreboard.v1` with exact evidence hashes, failure-class totals, unobserved fields held null, and a deterministic evidence rank.
- If a Combine task has an undeclared agent, duplicate candidate, missing event, stale or tampered event, mismatched task id, or duplicate task result, then the system shall return a blocked Combine result without producing a passing scoreboard.
- When `factory license verify` or `factory combine verify` receives an artifact, the system shall verify the canonical hash and all derived fields offline. Optional DSSE sealing shall use the existing Receipt v2 trust-root verifier; a locally hash-bound artifact shall never be described as signed without a verified envelope.
- When Graph Ops or MCP reads license or Combine state, the system shall be read-only and shall not execute an agent, apply a repair, approve, merge, publish, deploy, sign, message, access credentials, or call a connector.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Current clean governed evidence earns bounded autonomy
  Given twenty current clean governed events with independent verifier receipts
  And every event shares one requested workspace path
  When factory license status reads the agent identity
  Then it returns an autonomous license only for that common path scope

Scenario: A severe failure immediately revokes autonomy
  Given an autonomous agent license
  And a current governed event classified hollow_test
  When factory license record accepts the event
  Then it writes an incident capsule
  And the derived license is human_controlled

Scenario: Admission cannot outrun evidence
  Given an agent whose derived license is supervised
  And an autonomous Loop Passport request that declares that agent
  When run admission is prepared
  Then it fails with E_LICENSE_EXCEEDED

Scenario: Combine compares proof rather than vendor claims
  Given a sealed task with two declared agents and two matching governed events
  When factory combine score runs
  Then it emits an offline-verifiable scoreboard with no measured cost or speed claim

Scenario: A changed scoreboard is rejected offline
  Given a factory.combine-scoreboard.v1 artifact
  And one changed derived rank
  When factory combine verify runs
  Then it returns COMBINE_SCOREBOARD_INVALID
```

## SHOULD — Technical/structural

- ADR references: `docs/EARNED_AUTONOMY.md`, `docs/GAUNTLET.md`, and
  `docs/SIGNED_RECEIPTS.md`.
- Data model: immutable JSON events under `.factory/agent-licenses/`, current
  local incident capsules, sealed Combine task declarations, scoreboards, and
  optional Receipt v2 DSSE envelopes.
- API contract: `factory license`, `factory combine`, one admission check,
  Graph Ops projections, and read-only MCP tools.

## SHOULD NOT — Implementation details

- Do not claim external identity authentication, vendor quality rankings,
  productivity, cost, token savings, or a global benchmark.
- Do not infer agent identity, run arbitrary commands, auto-repair, self-promote,
  auto-approve, merge, publish, deploy, or consume a credential.
- Do not retain prompts, source bodies, connector secrets, or raw transcripts in
  the license ledger or Combine scoreboard.
- Do not call a hash-bound local artifact cryptographically signed unless its
  optional DSSE envelope validates against the supplied trust root.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | admission, identity, verifier, or receipt binding is invalid | reject without a ledger write |
| 2 | latest event has a severe failure class | human_controlled plus incident capsule |
| 3 | fewer than five clean events since latest incident | human_controlled |
| 4 | latest governed evidence is older than thirty days | supervised decay |
| 5 | twenty current clean events, fifteen independent verifier receipts, and common scope | autonomous for common scope |
| 6 | current clean governed evidence but insufficient autonomy policy | supervised or human_controlled |
| 7 | requested passport level or path exceeds license | E_LICENSE_EXCEEDED |
| 8 | Combine inputs are exact, complete, and task-bound | emit canonical scoreboard |
| 9 | Combine artifact or derived view hash differs | COMBINE_SCOREBOARD_INVALID |
