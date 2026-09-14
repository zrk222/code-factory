# Spec: stateless-replay-hints-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Code Factory shall attach deterministic retry and cache guidance to each
one-shot stateless MCP response. The guidance helps a client deduplicate its
own retries and revalidate a cached response without creating server-side
state or changing the read-only authority boundary.

### User roles

- IDE or CI client deciding whether a stateless response can be retried locally.
- Human reviewer checking that cache guidance is bounded and non-authoritative.
- Code Factory maintainer verifying the hint contract remains deterministic.

### Declared facts

- `request_key_bound`: the request key is the canonical request SHA-256 digest.
- `response_key_bound`: non-null responses carry a SHA-256 digest of canonical
  response JSON.
- `retry_safe`: one-shot MCP handlers are read-only and safe for a client to
  retry as a fresh request.
- `server_replay_store_absent`: no replay ledger or deduplication store exists.
- `serverReplayStore`: the response explicitly reports `false` for a server
  replay store.
- `client_hint_only`: cache guidance is a client-only hint, not a server
  cache contract.
- `cache_ttl_bounded`: successful non-error responses use a client TTL from
  0 through 900 seconds, defaulting to 300 seconds.
- `error_notification_uncacheable`: errors and notifications have TTL 0.
- `inputs_valid`: the request digest, response serialization, and TTL satisfy
  the bounded input contract.
- `authority_none`: all execution, approval, publication, deployment, signing,
  credential, connector, and messaging authority remains false.

### Requirements (EARS)

- When `REQ_REPLAY_HINTS` has `request_key_bound` and `inputs_valid` true, the system shall return `factory.mcp.replay-hints.v1` marked `MCP_STATELESS_REPLAY_HINTS` with request/response digests, safe retry facts, and an authority-free client-only cache hint. [R1]
- When `REQ_SUCCESS_CACHE` receives a normal non-error result, the system shall return `cacheable: true` with the bounded default TTL of 300 seconds unless a caller supplies another integer from 0 through 900. [R2]
- When `REQ_ERROR_CACHE` receives an error or notification (`None`) response, the system shall return `cacheable: false` with `ttlSeconds: 0`. [R3]
- When `REQ_INPUT_BOUNDS` receives a request digest, TTL, or response outside the bounded input contract, the system shall reject the input with `MCP_REPLAY_HINTS_INVALID` without I/O. [R4]
- When `REQ_STATELESS_PROJECTION` receives a `dispatch_stateless` envelope, the system shall emit the replay hints without changing its one-shot, no-server-state, read-only behavior. [R5]

### Acceptance criteria

```gherkin
Scenario: A successful response receives deterministic client hints
  Given REQ_REPLAY_HINTS and REQ_SUCCESS_CACHE and a valid request digest and a normal JSON response
  When replay hints are built twice
  Then both payloads match, retries are safe, the request and response digests are present, and the cache TTL is 300 seconds

Scenario: Error and notification responses cannot be cached
  Given REQ_ERROR_CACHE and an MCP error response or a notification response
  When replay hints are built
  Then cacheable is false and ttlSeconds is 0

Scenario: Invalid bounds fail closed
  Given REQ_INPUT_BOUNDS and an uppercase or malformed request digest or a TTL outside 0 through 900
  When replay hints are built
  Then MCP_REPLAY_HINTS_INVALID is raised without reading or writing files

Scenario: Stateless dispatch exposes hints without authority
  Given REQ_STATELESS_PROJECTION and a valid tools/list stateless request
  When dispatch_stateless returns
  Then the envelope contains MCP_STATELESS_REPLAY_HINTS and every authority flag is false

Scenario: Every requirement has an observable validator marker
  Given the stateless replay-hints contract
  When strict validator mutation runs
  Then markers include `MCP_STATELESS_REPLAY_HINTS`, `MCP_REPLAY_HINTS_INVALID`, `client_hint_only`, `serverReplayStore`, and `authority_none`
```

## SHOULD - Technical and structural

- API: `build_stateless_replay_hints(request_sha256, response, ttl_seconds=300)`.
- Response hashes use sorted-key, compact UTF-8 JSON canonicalization.
- The default cache hint is client-only and must be revalidated with a fresh
  request; no server cache or replay ledger is implied.

## SHOULD NOT - Non-goals

- Do not create a replay database, session, cursor, or server-side dedupe.
- Do not claim provider HTTP caching, exactly-once delivery, or execution
  idempotency for a future mutating transport.
- Do not execute commands, mutate files, approve work, or contact providers.

## Decision logic

| # | if | then |
|---|---|---|
| 1 | request digest or TTL is outside the schema | raise `MCP_REPLAY_HINTS_INVALID` |
| 2 | response is `None` or contains an MCP `error` object | retry safe, cacheable false, TTL 0 |
| 3 | response is a normal JSON result | retry safe, cacheable true, bounded TTL, response digest |
| 4 | `inputs_valid` is true | return deterministic authority-free hints |
