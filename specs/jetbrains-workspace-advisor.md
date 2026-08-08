# Spec: jetbrains-workspace-advisor

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Provide a local, bounded **Workspace Load Advisor + Remote/WSL Preflight** for
the FactoryLine CLI, MCP adapter, and JetBrains tool window. It shall make
workspace shape visible before a developer manually changes a project setting
or investigates remote-path friction. It is an observation surface, not an IDE
performance diagnosis or automatic optimizer.

### User roles

- Professional developer: needs a quick, trustworthy local brief before
  reviewing an unwieldy workspace or a WSL/UNC setup.
- Platform engineer: needs a local artifact to discuss generated directories,
  project roots, shared-index suitability, and remote-path assumptions.
- Reviewer: needs to confirm that the diagnostic did not modify source,
  configuration, IDE state, or remote infrastructure.

### Requirements (EARS)

- The system shall emit schema `factory.workspace_advisor.v1`, marker `WORKSPACE_ADVISOR_LOCAL_READ_ONLY`, marker `WORKSPACE_ADVISOR_SCHEMA_BOUND`, and marker `WORKSPACE_ADVISOR_NOT_PERFORMANCE_DIAGNOSIS` from an existing workspace.
- When `factory workspace inspect --root WORKSPACE_ROOT` runs without `--out-dir`, the system shall return a report containing only bounded local filesystem and local path/runtime facts, shall create no artifact, and shall emit `WORKSPACE_ADVISOR_NO_WRITE_DEFAULT`.
- The system shall emit marker `WORKSPACE_ADVISOR_SCAN_BOUNDED` and return a `scan` object with `.git` excluded, symlinked directories untraversed, a maximum of 20,000 regular files, and `scan_limited=true` when the maximum is reached.
- The system shall emit marker `WORKSPACE_ADVISOR_FACTS_MEASURED` and return measured `files_scanned`, `bytes_scanned`, `managed_directory_summary`, recognized local manifests, and a path-only local/UNC/WSL classification without reading credential values.
- When managed directory evidence has measured bytes greater than zero, the scanned count is at least 5,000 files, or scan_limited is true, the system shall emit `WORKSPACE_ADVISOR_REVIEW_PATHS`, return explicit manual review paths with triggering evidence and a no-mutation boundary, and not return a performance-improvement promise.
- If the output directory resolves below the current workspace, the system shall emit `WORKSPACE_ADVISOR_ARTIFACTS_EXPLICIT` and write local JSON, Markdown, and Mermaid files; if it resolves outside, it shall fail with `WORKSPACE_ADVISOR_OUTPUT_OUTSIDE_ROOT` without a write.
- When the JetBrains action is selected, the system shall display explicit local-workspace confirmation and, after confirmation, invoke only the configured direct executable with `workspace inspect --root PROJECT_ROOT --json` and emit `WORKSPACE_ADVISOR_CONFIRMATION_REQUIRED`.
- The system shall return `factory.workspace_advisor` through the stdio adapter as an in-memory read-only report with marker `MCP_WORKSPACE_ADVISOR_READ_ONLY`; the stdio adapter shall create no report artifact.
- The system shall emit marker `WORKSPACE_ADVISOR_ZERO_AUTHORITY` and return an authority object with `execution=false`, `ide_settings=false`, `cache_mutation=false`, `indexing_mutation=false`, `remote_connection=false`, `credential=false`, `publication=false`, and `deployment=false`.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: observe a generated and dependency-heavy workspace
  Given a local workspace contains build output and a dependency directory
  When Workspace Advisor inspects it without an output directory
  Then `WORKSPACE_ADVISOR_LOCAL_READ_ONLY` is emitted
  And a local measurement result is returned
  And no report artifact is created

Scenario: retain the incomplete-scan boundary
  Given a workspace contains more regular files than the selected scan cap
  When Workspace Advisor runs
  Then `scan_limited=true` is returned
  And `WORKSPACE_ADVISOR_NOT_PERFORMANCE_DIAGNOSIS` is emitted

Scenario: make a report only on explicit request
  Given a local workspace and an artifact directory below it
  When the developer requests Save local report
  Then a local report is written below that directory
  And `execution=false` is returned

Scenario: preserve adapter authority
  Given a local stdio client requests factory.workspace_advisor
  When the server returns its report
  Then `MCP_WORKSPACE_ADVISOR_READ_ONLY` is returned
  And no report artifact is created

Scenario: retain all advisor boundaries
  Given Workspace Advisor is available
  When a developer opens the advisor surface
  Then the receipt records `WORKSPACE_ADVISOR_SCHEMA_BOUND`, `WORKSPACE_ADVISOR_NO_WRITE_DEFAULT`, `WORKSPACE_ADVISOR_SCAN_BOUNDED`, and `WORKSPACE_ADVISOR_FACTS_MEASURED`
  And the receipt records `WORKSPACE_ADVISOR_REVIEW_PATHS`, `WORKSPACE_ADVISOR_ARTIFACTS_EXPLICIT`, `WORKSPACE_ADVISOR_CONFIRMATION_REQUIRED`, and `WORKSPACE_ADVISOR_ZERO_AUTHORITY`
  And the receipt records `factory.workspace_advisor.v1`, `factory workspace inspect --root WORKSPACE_ROOT`, `.git`, `files_scanned`, `managed_directory_summary`, and `--out-dir`
  And the receipt records `workspace inspect --root PROJECT_ROOT --json`, `factory.workspace_advisor`, and `execution=false`
```

## SHOULD - Technical/structural

- Keep the local advisor in a dedicated standard-library Python module; make
  CLI and MCP thin delegates over the same inspection function.
- Parse only the fixed report schema in the Kotlin adapter; unknown output is
  an unavailable state, never a performance finding.
- Present recommendations as human-controlled review paths and link users to
  JetBrains Shared Indexes documentation rather than configuring it.
- The bounded implementation may use `0` for empty counters and non-positive
  validation, `1` for first-position slicing, `2` for stable JSON indentation,
  `8` for the UTF-8 label, `20` for a bounded large-file shortlist, and
  `20000` for the maximum regular-file scan cap. These are implementation
  mechanics, not performance targets or remediation promises.

## SHOULD NOT - Implementation details

- Do not query the JetBrains heap/GC/indexer, execute a build/test, disable
  inspections/plugins, invalidate caches, alter project files, connect to
  WSL/Gateway/Docker/SSH, access credentials, upload source, or claim a
  measured performance improvement.
