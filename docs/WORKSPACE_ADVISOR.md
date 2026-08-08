# Workspace Load Advisor + Remote/WSL Preflight

FactoryLine's Workspace Load Advisor gives a developer a bounded, local
filesystem measurement before they manually change JetBrains project settings
or troubleshoot a remote workspace. It is deliberately a **diagnostic brief**,
not an automatic performance tuner.

```powershell
# Observe only: writes nothing.
factory workspace inspect --root . --json

# Write an explicit local handoff packet only when requested.
factory workspace inspect --root . --out-dir .factory/workspace-advice --json
```

The optional output directory contains JSON, Markdown, and Mermaid files. The
command rejects an output directory outside the selected workspace.

## What it measures

- Bounded count and byte total for regular local files (at most 20,000 files).
- Largest local files plus top-level and managed generated/dependency/IDE
  directory summaries.
- Recognized project ecosystem manifests.
- A path-only workspace classification: local Windows/POSIX, Windows UNC,
  WSL UNC, or a Linux process running under WSL.

The analysis skips `.git`, does not traverse symlinked directories, and marks a
scan as limited rather than pretending it inspected every file.

## What it suggests

When the measured facts warrant it, the advisor proposes review paths such as:

- Review generated-output directories in JetBrains project-exclusion settings.
- Confirm managed dependency/build directories are not also ordinary source
  roots.
- Evaluate [JetBrains Shared Indexes](https://www.jetbrains.com/help/idea/shared-indexes.html)
  for a large team workspace using JetBrains' supported process.
- For WSL/UNC context, verify that IDE, runtime, build tools, and
  container/WSL path mappings agree before a remote run.

These are suggestions for a developer or platform team to evaluate. FactoryLine
does not create, download, or configure shared indexes.

## Hard boundary

The advisor never changes heap settings, GC settings, caches, indexing,
inspections, plugins, project files, remote/Gateway/WSL/Docker/SSH state,
credentials, or network state. It does not run a build or test. It does not
measure CPU, IDE heap, garbage collection, indexing time, UI latency, freezes,
or remote connectivity, and therefore never claims to diagnose or repair those
conditions.

The JetBrains tab runs the same local CLI command only after workspace
confirmation. `factory.workspace_advisor` exposes the same report through the
local stdio MCP server in memory only; MCP writes no report artifacts and grants
no execution or configuration authority.
