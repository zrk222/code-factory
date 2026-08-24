# Spec: JetBrains Guardian Core

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Give a JetBrains developer one local-first Guardian view for an IDE that feels
slow, is indexing, or contains an unclear AI-generated change. The view turns
the existing bounded IDE Health recorder and explicit proof tools into a short,
evidence-led investigation: current signals, a small incident timeline, and
manual next-review paths.

Guardian Core is an observation and navigation surface. It never assigns a
root cause, computes a synthetic health score, changes IDE settings, disables a
plugin, invalidates a cache, starts a CLI command, or applies a fix.

### User roles

- JetBrains developer who needs to distinguish an observed symptom from a
  guessed cause before changing an IDE or project.
- Senior developer or team lead who needs a compact local handoff for a slow
  IDE or an AI-assisted diff without sharing source, credentials, or telemetry.

### Requirements (EARS)

- The system shall show a dedicated `Guardian` tool-window tab before advanced
  FactoryLine tabs and shall state that its signals are local observations, not
  a causal diagnosis.
- When no `health_sample` exists, the system shall return `state=NO_DATA` and
  offer only `start_local_recording`; it shall not report the IDE as healthy.
- When `elevated_signal_count` is greater than zero, the system shall return
  `state=ATTENTION` and render each exact threshold observation without naming
  a cause.
- While `sample_count` is from 1 through 20, the system shall return a bounded
  `incident_timeline` derived only from indexing state transitions and threshold
  crossings in that sample window.
- If `process_cpu_percent` is unavailable, the system shall return
  `process_cpu=unavailable` and shall not return a numeric CPU value or
  inference.
- When a developer selects a review route, the system shall navigate to the
  existing local `IDE Health`, `Index Continuity`, `Workspace Advisor`, `Proof
  Review`, or `Intent Ledger` tab without executing a CLI command.
- The system shall render fixed `safe_review_options` as manual review paths
  and shall not mutate IDE settings, caches, indexes, plugins, inspections,
  project files, VCS state, remote state, or credentials.
- The system shall emit a JetBrains Marketplace compliance
  checklist and reviewer summary that distinguish deterministic package
  evidence from Vendor-account and manual-review facts; its local release gate
  shall fail when the generated package lacks the declared Guardian metadata,
  40 by 40 SVG icons, safe archive shape, or a compatible Plugin Verifier
  verdict.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: no recording has been captured
  Given a project with no in-memory health samples
  When the developer opens Guardian
  Then Guardian reports that no local samples are available
  And it offers start_local_recording
  And it does not report a healthy IDE

Scenario: elevated EDT signal remains non-causal
  Given a local sample with EDT delay of 250 ms or greater
  When Guardian renders the sample window
  Then it shows the exact EDT observation
  And it adds an incident timeline event
  And it does not name a plugin, cache, or root cause

Scenario: a review route is navigation only
  Given Guardian offers a continuity review option
  When the developer selects that option
  Then the Index Continuity tab opens
  And no FactoryLine CLI command is started
  And no IDE setting or cache changes

Scenario: CPU is unavailable
  Given a local runtime without process CPU metrics
  When Guardian renders the sample window
  Then it renders CPU as unavailable
  And it does not render a numeric CPU value
```

## SHOULD - Technical and structural boundary

- ADR references: `adr/0001-failure-aware-assembly.md`
- Data model: `guardian_assessment` (`sample_count`: integer 0 through 20,
  `elevated_signal_count`: non-negative integer, `indexing_active_count`:
  non-negative integer, `state`: `NO_DATA|READY|OBSERVE|ATTENTION`, `signals`:
  list, `timeline`: list), derived only in memory from existing `health_sample`
  objects. An elevated signal is exactly EDT >=250 ms, available process CPU
  >=80 percent, or heap use >=85 percent.
- API contract: internal Kotlin value objects only; no network, telemetry, or
  persistent Guardian database.
- UI layout contract: Guardian review controls use an 8-pixel horizontal gap
  and zero vertical gap; this is presentation-only and grants no execution
  authority.
- Release evidence contract: the scoped Marketplace workflow may package and
  verify the candidate, but must not claim Marketplace approval, dispatch a
  publish job, or replace a pending update without the separate external gate.

## SHOULD NOT - Implementation details

- Do not claim a plugin, index, cache, inspection, codebase, or setting caused
  a symptom.
- Do not add a numeric health score or a plugin-impact ranking.
- Do not add automated repair, cache invalidation, setting changes, or a
  background workspace scan.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | no `health_sample` exists | return `state=NO_DATA` |
| 2 | `elevated_signal_count` is greater than zero | return `state=ATTENTION` |
| 3 | `elevated_signal_count` is zero and `indexing_active_count` is greater than zero | return `state=OBSERVE` |
| 4 | `elevated_signal_count` is zero and `indexing_active_count` is zero | return `state=READY` |
