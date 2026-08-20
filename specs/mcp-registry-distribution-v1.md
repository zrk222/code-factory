# Spec: mcp-registry-distribution-v1

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Publish the existing Code Factory local, stdio-only MCP facts to the Official MCP
Registry without changing server authority. An MCP-capable client must be able
to discover the released PyPI package and start the existing local adapter;
the server remains read-only and local to the caller workspace.

### User roles

- **Coding-assistant user:** discovers the local Code Factory proof surface from
  an MCP registry and chooses whether to configure it in a supported client.
- **Release maintainer:** creates a GitHub release; the release workflow may
  publish the corresponding registry metadata only after PyPI publication and
  metadata checks succeed.

### Requirements (EARS)

- The system shall emit `MCP_REGISTRY_DESCRIPTOR`.
- The system shall emit a descriptor named `io.github.zrk222/code-factory`.
- The system shall return package form `factoryline-code-factory==0.40.0`.
- The system shall return launch command `factory mcp serve`.
- When a release tag equals `v0.40.0`, the workflow shall return release-metadata readiness.
- The system shall emit status `PYPI_MCP_OWNERSHIP_MARKER_VERIFIED`.
- If `RELEASE_METADATA_DRIFT` occurs, then the workflow shall reject registry authentication and publication.
- The system shall emit status `MCP_REGISTRY_METADATA_REJECTED`.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: A registry client starts the released local MCP server
  Given `MCP_REGISTRY_DESCRIPTOR`
  And `io.github.zrk222/code-factory`
  And `factoryline-code-factory==0.40.0`
  And `factory mcp serve`
  When a registry client resolves its PyPI package entry
  Then the system returns `MCP_REGISTRY_DESCRIPTOR`

Scenario: Metadata drift blocks registry publication
  Given `RELEASE_METADATA_DRIFT`
  When the MCP Registry workflow preflight runs
  Then the system returns `MCP_REGISTRY_METADATA_REJECTED`

Scenario: PyPI ownership is visible before metadata publication
  Given `v0.40.0`
  When the matching PyPI package marker is visible
  Then the system returns `PYPI_MCP_OWNERSHIP_MARKER_VERIFIED`
```

## SHOULD - Technical/structural

- The registry publisher binary is pinned to `v1.8.1` and checked against the
  upstream release checksum before execution.
- The source distribution includes `mcp/server.json` as inspectable release
  metadata.
- Tests validate the descriptor, ownership marker, release workflow ordering,
  and package-data rule without requiring registry credentials.

## SHOULD NOT - Implementation details

- Do not add a hosted MCP service, automatic client configuration, provider
  credentials, an MCP write tool, an execution control, or a claim of universal
  client compatibility.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `MCP_REGISTRY_DESCRIPTOR` | emit `MCP_REGISTRY_DESCRIPTOR` |
| 2 | `v0.40.0` | return `PYPI_MCP_OWNERSHIP_MARKER_VERIFIED` |
| 3 | `RELEASE_METADATA_DRIFT` | return `MCP_REGISTRY_METADATA_REJECTED` |
