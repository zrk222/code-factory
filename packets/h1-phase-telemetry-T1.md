# TASK PACKET T1 — h1-phase-telemetry
<!-- One session. Finish, verify, stop. Context resets after this. -->

## Your single task
add one bounded invocation-local collector and capture entrypoint startup through lifecycle receipt preparation.

## Slice (you may only create/modify files here + tests)
factoryline

## Files in scope (R_f — read nothing else except context/PROGRESS.md)
- factoryline/ops_telemetry.py
- factoryline/provenance.py
- tests/test_ops_telemetry.py

## Complete governing specification
# Spec: h1-phase-telemetry
Status: approved
SpecFactor-target: 0.75â€“2.5

## MUST â€” Functional core
### Description
Add privacy-safe, bounded phase observations to existing local CF lifecycle receipts so the critical path can be measured before further optimization.

### User roles
- Local CF operator reviewing a scan, proof plan, or child-process run.

### Requirements (EARS)
- The system shall emit at most `PHASE_RECORD_LIMIT` `12` phase records per invocation, with each duration and counter represented as a non-negative integer, in the existing lifecycle receipt without changing command results, stable scan identity, proof verification, or authority.
- When no source is eligible, the system shall return the scanner's existing `NO_SOURCES` result and the exit code defined by that existing route.
- If an instrumented phase fails, the system shall preserve its existing error and cleanup behavior, emit a `CLOSED_ERROR_CODE`, and shall not expose arguments, paths, source, environment, logs, or raw exception text.
- If lifecycle receipt serialization or persistence fails, the command shall return its original command result and the telemetry writer shall perform at most `RECEIPT_WRITE_LIMIT` `1` receipt write.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: source-bearing scan and proof planning
  Given identical local fixture inputs
  When phase telemetry is enabled
  Then no more than `PHASE_RECORD_LIMIT` `12` phase records are emitted and semantic behavior matches the uninstrumented run

Scenario: scan has no eligible source
  Given a workspace with no eligible Python sources
  When the existing scanner runs
  Then its existing `NO_SOURCES` result and defined exit code are preserved

Scenario: phase failure or interrupted child
  Given a phase raises or a child is interrupted
  When the instrumented path runs
  Then the existing error and cleanup disposition is preserved and telemetry records `CLOSED_ERROR_CODE` without private input data

Scenario: lifecycle receipt write fails
  Given lifecycle receipt serialization or persistence fails
  When the command completes
  Then the original command result is returned and no more than `RECEIPT_WRITE_LIMIT` `1` receipt write is attempted
```

## SHOULD â€” Technical/structural
- Scope: existing `provenance.py`, `cli.py`, `ops_telemetry.py`, `adoption.py`, `proof_reuse.py`, `assembly_process.py` and their existing focused tests.
- One invocation-local accumulator; one bounded lifecycle `phase_telemetry` field; no new module, persistent cache, independent receipt stream, new I/O, public API break, or cap increase.
- Preserve `scan_sha256`; compare proof canonical behavior projections and stable per-proof keys. Proof plan hash is volatile because routing timing is included.
- Lifecycle self-serialization/write completion cannot be included in that same immutable receipt. Measure overhead externally; never perform a second write.
- Parent limit: phases must be honest about coverage. Source bytes/parse counts may be emitted only at an existing observation boundary; no extra reads or inferred counts.

## SHOULD NOT â€” Implementation details
- No command argument retention, source/path/environment/log/error-message capture, new authority, or success upgrade for no-source scans.

## Decision logic (factory candidates)
No independent factory candidate rules; receipt phases are descriptive measurements only and cannot change scan, proof, or process outcomes.


## CONSTITUTION DIGEST: one task only; read ONLY listed files; tests ship with code; never touch skeleton/; never add deps without ADR; never leave stubs; decision logic goes to the factory, not inline; stop and ask on ambiguity.

## Definition of done
Run: `python -m pytest tests/test_ops_telemetry.py -q` — must pass. Then STOP and report the diff summary.
