# Spec: stateless-mcp-request-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Code Factory shall offer a one-shot, local MCP request path for callers that
cannot keep a server session. A request is self-contained, bounded, and
hash-addressed; it may read existing proof context only and cannot acquire
execution or provider authority.

### User roles

- Developer or CI bridge submitting one reviewed JSON-RPC request.
- Coding agent consuming the bounded response envelope.
- Human reviewer checking the request digest and explicit claim boundary.

### Declared facts

- `request_self_contained`: one JSON-RPC object is evaluated once.
- `request_size_bounded`: canonical request bytes are at most 65,536.
- `request_extensions_allowed`: only `jsonrpc`, `id`, `method`, and `params` are accepted.
- `request_valid`: the value is a JSON-RPC object with string keys and valid UTF-8 JSON representation.
- `canonical_size_within_limit`: canonical request bytes are no more than 65,536.
- `core_fields_only`: no top-level field exists outside the four core fields.
- `path_confined`: a CLI request path is relative, stays beneath the selected workspace, and names an existing `.json` file.
- `response_hash_bound`: the envelope carries SHA-256 of canonical request bytes.
- `server_state_none`: no request history, cursor, session, or mutable server state is retained.
- `authority_none`: execution, approval, publication, deployment, signing, credential, connector, and messaging authority remain false.

### Requirements (EARS)

- When `REQ_STATELESS_REQUEST` receives one JSON-serializable JSON-RPC object at or below 65,536 canonical UTF-8 bytes with only the core fields, it shall dispatch the existing read-only handler once and return `factory.mcp.stateless-response.v1` marked `MCP_STATELESS_RESPONSE`, including `request_sha256`, `state: stateless`, `server_state: none`, and authority false, without writing workspace files. [R1]
- When `REQ_STATELESS_REJECTION` receives a stateless request containing a session, cursor, state, resume, or unknown top-level extension, exceeding 65,536 canonical UTF-8 bytes, malformed or non-object, it shall fail closed with `MCP_STATELESS_STATE_REJECTED`, `MCP_STATELESS_REQUEST_TOO_LARGE`, or `MCP_STATELESS_REQUEST_INVALID` as applicable, without dispatching the request. [R2]
- When `REQ_STATELESS_CLI` runs `factory mcp request request.json --root C:\work\my-mvp --json` with an absolute, parent-traversing, missing, or non-JSON request path, it shall fail closed with `MCP_STATELESS_REQUEST_PATH_REJECTED` before dispatch and without writing the workspace. [R3]

### Acceptance criteria

```gherkin
Scenario: A self-contained request returns a stable envelope
  Given REQ_STATELESS_REQUEST and a valid tools/list JSON-RPC object
  When it is evaluated twice through dispatch_stateless
  Then both envelopes match and carry the same request_sha256, state stateless, and server_state none

Scenario: Stateful extensions cannot enter the one-shot path
  Given REQ_STATELESS_REJECTION and a request containing sessionId, cursor, or state
  When stateless dispatch is attempted
  Then it fails with MCP_STATELESS_STATE_REJECTED before dispatch

Scenario: Oversized input fails closed
  Given REQ_STATELESS_REJECTION and canonical request bytes greater than 65,536
  When stateless dispatch is attempted
  Then it fails with MCP_STATELESS_REQUEST_TOO_LARGE

Scenario: The CLI cannot escape the workspace
  Given REQ_STATELESS_CLI and an absolute or parent-traversing request path
  When `factory mcp request request.json --root C:\work\my-mvp --json` is invoked with that path
  Then it fails with MCP_STATELESS_REQUEST_PATH_REJECTED
```

## SHOULD - Technical and structural

- API: `dispatch_stateless(request, root)` and `factory mcp request request.json --root C:\work\my-mvp [--json]`.
- Canonical digest uses UTF-8 JSON with sorted keys and compact separators.
- Existing `factory mcp serve` remains the long-lived newline-delimited stdio path.
- The implementation uses only the existing local read-only MCP handlers.

## SHOULD NOT - Non-goals

- Do not create a hosted HTTP endpoint or retain server/session state.
- Do not execute commands, mutate files, approve work, publish, deploy, sign, message, access credentials, or call providers.
- Do not treat a response envelope as proof that a client consumed, accepted, or acted on the result.

## Decision logic

| # | if | then |
|---|---|---|
| 1 | `request_valid` is false | return `MCP_STATELESS_REQUEST_INVALID` |
| 2 | `canonical_size_within_limit` is false | return `MCP_STATELESS_REQUEST_TOO_LARGE` |
| 3 | `core_fields_only` is false | return `MCP_STATELESS_STATE_REJECTED` |
| 4 | `path_confined` is false | return `MCP_STATELESS_REQUEST_PATH_REJECTED` |
| 5 | `request_valid`, `canonical_size_within_limit`, `core_fields_only`, and `path_confined` are true | dispatch once and return a hash-bound authority-free envelope |
