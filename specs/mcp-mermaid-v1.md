# Spec: mcp-mermaid-v1

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Code Factory shall expose a local stdio MCP inspection server so an agent can
consume the deterministic Graph Ops facts used by the CLI and Factory Studio.
The server is an adapter, not an authority: it cannot execute a command,
mutate a workspace, approve work, publish, deploy, sign, access credentials,
grant a connector, or send a message.

Each completed starter emitted by `factory create`, `factory mvp`,
`factory app from-prd`, or `factory app from-prompt` shall contain a generated
Mermaid output map. The map is a file inventory and proof-boundary aid; it does
not certify product completeness, test coverage, or production readiness.

### User roles

- Coding agent needing compact, authoritative workspace context.
- Developer inspecting exact proof impact before rerunning a gate.
- New user opening a generated starter and needing a visual file inventory.
- Reviewer checking that an agent cannot self-authorize external effects.

### Requirements (EARS)

- The system shall return marker `FACTORY_MCP_LOCAL_READ_ONLY` with one `factory.mcp.status.v1` status payload for a workspace root, transport `stdio`, and false execution, approval, publication, deployment, signing, messaging, credential, and connector authority values. [R1]
- When one MCP initialization request is received, the system shall return marker `MCP_INITIALIZED`, protocol version `2025-03-26`, server name code-factory, and exactly the tools and resources capabilities. [R2]
- The system shall return marker `FACTORY_MCP_TOOL_INVENTORY` with exactly four MCP tool definitions named `factory.status`, `factory.graph_ops`, `factory.graph_impact`, and `factory.next_action`. [R3]
- When one graph snapshot or next-action MCP tool is called for a workspace root, the system shall return marker `MCP_GRAPH_OPS_PARITY` with values derived from graph_ops_snapshot for that workspace root and shall write 0 workspace files. [R4]
- When one graph-impact MCP tool receives 1 to 50 changed paths, each 1 to 512 characters, root-relative, non-empty, and without dot-dot, the system shall return marker `MCP_GRAPH_IMPACT_PARITY` with exactly graph_ops_impact(workspace_root, changed_paths) and shall write 0 workspace files. [R5]
- If one MCP request is malformed JSON-RPC, invalid arguments, an unknown tool, an absolute changed path, a changed path containing parent traversal, or a missing workspace root, the system shall return marker `MCP_INVALID_PARAMS_REJECTED`, JSON-RPC error -32602, and shall write 0 workspace files. [R6]
- When an unknown MCP method is requested, the system shall return marker `MCP_UNKNOWN_METHOD_REJECTED`, JSON-RPC error `-32601`, and shall write 0 workspace files. [R7]
- The system shall return marker `MCP_RESOURCES_PARITY` with exactly two MCP resources, `factory://status` and `factory://graph`, whose UTF-8 JSON text equals the local status or Graph Ops payload for the workspace root. [R8]
- When one target compiler starter reaches compiled-blocked, the system shall write marker `CODE_FACTORY_OUTPUT_MAP_V1` into one docs/CODE_FACTORY_OUTPUT_MAP.md with Mermaid flowchart TD, a source SHA-256 prefix, blocked promotion text, and one node for every output file including the map and .factory/target-compile-receipt.json. [R9]
- When one target compile receipt is written, the system shall return marker `OUTPUT_MERMAID_MAP_WRITTEN`, store the output map path and SHA-256 in that receipt, and include the map in the receipt file digest set. [R10]
- When one independent app-builder scaffold is written, the system shall write marker `APP_OUTPUT_MAP_WRITTEN` into one `docs/CODE_FACTORY_OUTPUT_MAP.md` with one node for every scaffold file, and return the map path plus SHA-256 in the scaffold result. [R11]
- The system shall emit marker `MCP_STDLIB_ONLY` from the MCP server and output map using only Python standard library code and existing Code Factory domain functions. [R12]
- When an operator starts the Open VSX release workflow for an immutable repository version tag, the system shall test and package one VSIX candidate, bind it to a SHA-256 manifest, require protected-environment `OPENVSX_TOKEN` only when `publish` is true, and refuse a branch, missing token, or altered candidate. [R13]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: An agent receives the same graph facts as the CLI
  Given one workspace root with one stale recorded proof
  When the agent calls factory.graph_ops through the local MCP server
  Then the response graph SHA-256 equals graph_ops_snapshot for the workspace root
  And factory.next_action returns the snapshot recommendation
  And the workspace root has 0 changed files

Scenario: An agent analyzes a changed proof input without execution authority
  Given one workspace root with one changed path named input.txt
  When the agent calls factory.graph_impact with one changed path input.txt
  Then the response equals graph_ops_impact for the workspace root and input.txt
  And the workspace root has 0 changed files

Scenario: The MCP boundary rejects unsafe input
  Given one local MCP server with one workspace root
  When a caller requests an unknown tool or changed path ../outside.txt
  Then the response has JSON-RPC error -32602
  And the workspace root has 0 changed files

Scenario: A target has a complete visual output inventory
  Given one target compiler starter with status compiled_blocked
  When target compilation returns
  Then the output map contains every completed output path
  And the target compile receipt binds the map SHA-256
  And the map states blocked promotion pending product-specific proof

Scenario: An app-builder output has a visual output inventory
  Given one independent app-builder scaffold
  When app-builder generation returns
  Then the returned output-map path exists and has the returned SHA-256
  And the map contains every returned output file

Scenario: Every MCP and output-map requirement has an observable marker
  Given the MCP and output-map contract
  When strict validator mutation runs
  Then markers include `FACTORY_MCP_LOCAL_READ_ONLY`, `MCP_INITIALIZED`, `FACTORY_MCP_TOOL_INVENTORY`, `MCP_GRAPH_OPS_PARITY`, `MCP_GRAPH_IMPACT_PARITY`, `MCP_INVALID_PARAMS_REJECTED`, `MCP_UNKNOWN_METHOD_REJECTED`, `MCP_RESOURCES_PARITY`, `CODE_FACTORY_OUTPUT_MAP_V1`, `OUTPUT_MERMAID_MAP_WRITTEN`, `APP_OUTPUT_MAP_WRITTEN`, and `MCP_STDLIB_ONLY`

Scenario: An Open VSX candidate is protected before marketplace publication
  Given one immutable repository version tag and no Open VSX token in source control
  When the Open VSX workflow runs with publish false
  Then it tests and seals one VSIX plus SHA-256 manifest without publication
  And publication requires a protected environment, an explicit publish input, and OPENVSX_TOKEN
```

## SHOULD - Technical/structural

- ADR reference: `adr/factory-mcp-v1.md`.
- Data model: a workspace root is one existing directory; changed paths are a
  list bounded by R5; an output map is one UTF-8 Markdown file containing a
  Mermaid flowchart; an MCP request is one JSON-RPC object.
- API contract: newline-delimited JSON-RPC over local stdio only; resource and
  tool results return UTF-8 canonical JSON as text content.
- Map node IDs are deterministic positional identifiers and labels contain only
  root-relative paths. Source content and absolute paths are excluded.

## SHOULD NOT - Implementation details

- Do not add remote HTTP, SSE, Streamable HTTP, OAuth, or connector runtime.
- Do not make MCP an evidence or release authority; it adapts native Graph Ops.
- Do not report savings, cost, tokens, or productivity values.
- Do not create an Open VSX namespace, secret, credential, or listing from the workflow.
