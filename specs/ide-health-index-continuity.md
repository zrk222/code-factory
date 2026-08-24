# Spec: IDE Health and Index Continuity

Status: approved for implementation

## MUST — Functional core

### Description

Give a JetBrains developer two evidence-led controls for a slow or unstable IDE:

1. **IDE Health Flight Recorder** samples the current IDE process, heap, indexing
   state, and EDT dispatch delay locally while the developer asks it to run.
2. **Index Continuity Guard** captures a local workspace baseline and compares a
   later state for structural changes that can justify re-analysis or reindexing.

Neither control changes IDE settings, invalidates caches, changes project files,
contacts a network service, or claims a causal plugin diagnosis.

### User roles

- JetBrains developer investigating a current slow, freezing, or reindexing IDE.
- Team lead preparing a compact, local diagnostic brief for a teammate.

### Requirements (EARS)

- The system shall enforce `max_health_samples` by storing at most 20 in-memory `health_sample` records per `project_session` and displaying each `signal_source` or `unavailable` state.
- When the developer starts `health_recording`, the system shall record a `health_sample` containing `heap_bytes`, `process_cpu` when exposed by the JVM, `indexing_state`, and `edt_delay_ms`; the system shall not write project state or contact a network service.
- If the JVM cannot expose CPU, the system shall display `cpu_unavailable` as `process_cpu=unavailable` and shall not display a numeric `process_cpu` value.
- When the developer requests a continuity baseline, the system shall display `baseline_path_guard` and create versioned JSON `continuity_baseline` only at the workspace-contained `.json` path supplied by the developer.
- When the developer requests a continuity comparison, the system shall return `comparison_output` containing exact `changed_manifests`, `managed_directory_topology`, `source_root_topology`, and `path_classification` values.
- If a continuity baseline is malformed, outside the workspace, or uses an unknown schema, the system shall display `continuity_refusal` and reject `continuity_compare` with the stable `INDEX_CONTINUITY_ERROR` marker.
- The system shall enforce `review_scope` by returning exactly one value: `stable`, `targeted_reanalysis`, or `broad_reanalysis`; it shall not return an indexing-duration prediction or an index-corruption diagnosis.
- When the developer invokes the JetBrains Index Continuity Guard, the system shall enforce `guard_confirmation` by displaying the guard result in a dedicated tool-window tab and requiring local-workspace confirmation before it invokes `continuity_baseline` or `continuity_compare`.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: changed build manifest requires broad review
  Given a workspace with `baseline_path_guard`
  When its package lock or build manifest changes
  Then the comparison returns `comparison_output`
  And the comparison returns `changed_manifests`
  And the comparison returns `review_scope`
  And local `guard_confirmation` permits the comparison
  And no IDE setting or cache is changed

Scenario: unchanged workspace is stable
  Given a workspace with a captured continuity baseline
  When no structural input has changed
  Then the comparison returns `review_scope`
  And it contains no fabricated runtime or duration claim

Scenario: health recorder only retains explicit local samples
  Given the developer starts `health_recording`
  When `max_health_samples` is reached
  Then the recorder retains at most 20 `health_sample` records

Scenario: process CPU signal is unavailable
  Given a JetBrains runtime with `cpu_unavailable`
  When a health sample is captured
  Then the recorder displays `cpu_unavailable`
  And the recorder does not display a numeric `process_cpu` value

Scenario: malformed baseline stops comparison
  Given a malformed continuity baseline
  When the developer requests `continuity_compare`
  Then the system returns `continuity_refusal`
  And the system returns `INDEX_CONTINUITY_ERROR`
```

## SHOULD — Technical and structural boundary

Data model: `health_sample` (`heap_bytes`: non-negative integer, `process_cpu`:
non-negative decimal or `unavailable`, `indexing_state`: enum, `edt_delay_ms`:
non-negative integer), `continuity_baseline` (`changed_manifests`: hash-only
list, `managed_directory_topology`: path-count list, `source_root_topology`:
path list, `path_classification`: enum), `continuity_compare`
(`structural_drift`: enum).

- Health samples remain in plugin memory until the project closes. They contain
  aggregate process data only, never source, file contents, credentials, or
  network data.
- Continuity baselines are versioned JSON and hash only named structural files;
  no file content is stored in the report.
- Findings are correlations or structural review signals, not causal diagnoses.
- All remediation remains a human decision in the JetBrains IDE.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `structural_drift` equals `none` | return `review_scope=stable` |
| 2 | `structural_drift` equals `manifest` or `source_root` | return `review_scope=broad_reanalysis` |
| 3 | `structural_drift` equals `managed_directory` | return `review_scope=targeted_reanalysis` |
