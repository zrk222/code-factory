# Spec: assistant-neutral-mcp

Status: approved

## Purpose

Any coding assistant that supports local stdio MCP can inspect the same bounded
Code Factory proof context. An assistant without MCP receives an explicit CLI
handoff instead. Neither path grants execution or release authority.

## MUST — Functional core

### Requirements (EARS)

- When the requested client is supported as generic, Cursor, OpenCode, or Codex, the system shall emit a copy-only factory.mcp.setup.v1 packet with `MCP_CLIENT_RENDERED`. [REQ-MCP-CLIENT]
- When a configuration packet is rendered for an existing workspace root, the system shall return `MCP_COMMAND_BOUND`, the resolved root, and the exact `factory mcp serve --root` stdio command. [REQ-MCP-ROOT]
- When any configuration packet is rendered, the system shall return `MCP_COPY_ONLY`, false execution, approval, publication, deployment, signing, messaging, credential, and connector authority, and shall write no workspace or client file. [REQ-MCP-BOUNDARY]
- When a generic or named client packet is rendered, the system shall return `MCP_CLIENT_CONFIG_COPYABLE` with valid standard MCP command-and-arguments JSON or a copyable Codex command, never an applied configuration. [REQ-MCP-COPY]
- When the requested client is not one of the supported renderers, the system shall reject the request with `MCP_CLIENT_REJECTED`. [REQ-MCP-CLIENT-REJECT]
- When the requested workspace root does not resolve to an existing directory, the system shall reject the request with `MCP_ROOT_REJECTED`. [REQ-MCP-ROOT-REJECT]

## Acceptance scenarios

```gherkin
Scenario: Any stdio MCP client receives a portable proof connection
  Given an existing workspace root
  When factory mcp config --client generic is run
  Then it returns MCP_CLIENT_RENDERED and the exact local stdio command
  And no workspace file changes

Scenario: A non-MCP assistant retains a safe handoff
  Given an assistant that does not support local stdio MCP
  When the user reads the AI client guide
  Then it instructs the assistant to propose explicit Factory CLI commands
  And the human remains responsible for running and reviewing them
```

## SHOULD NOT — Implementation details

- The system shall not add a remote MCP endpoint, OAuth, server auto-start, client-config mutation, source upload, provider routing, or automatic tool execution.
- The system shall not claim that every coding assistant implements local stdio MCP.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `MCP_CLIENT_RENDERED` | emit `MCP_CLIENT_RENDERED` |
| 2 | `MCP_COMMAND_BOUND` | emit `MCP_COMMAND_BOUND` |
| 3 | `MCP_COPY_ONLY` | emit `MCP_COPY_ONLY` |
| 4 | `MCP_CLIENT_CONFIG_COPYABLE` | emit `MCP_CLIENT_CONFIG_COPYABLE` |
| 5 | `MCP_CLIENT_REJECTED` | reject with `MCP_CLIENT_REJECTED` |
| 6 | `MCP_ROOT_REJECTED` | reject with `MCP_ROOT_REJECTED` |
