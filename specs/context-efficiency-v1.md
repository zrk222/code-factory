# Spec: context-efficiency-v1

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

Context Efficiency shall create bounded, deterministic, hash-verified,
read-only context packets for agent hand-offs without executing source files,
network calls, provider actions, or release actions.

### Declared facts

- `request_schema`: `factory.context-efficiency-request.v1` has exactly seven required fields.
- `packet_schema`: `factory.context-efficiency-packet.v1` embeds the normalized request, source rows, budget, cache key, and packet digest.
- `verification_schema`: `factory.context-efficiency-verification.v1` reports `READY` or `BLOCKED` without authority.
- `status_schema`: `factory.context-efficiency-status.v1` reads at most 100 cache records and does not reread source bodies.
- `budget_bounds`: total is 256..12000 tokens and per-file is 32..2000 tokens; estimates use four UTF-8 bytes per token.
- `source_bounds`: changed paths and sources are each 1..128 entries; each source is at most 1 MiB and is read with before/after identity checks.
- `secret_boundary`: secret-shaped request keys and secret-shaped source names/content produce digest-only or a fail-closed refusal and never expose an excerpt.
- `refusal_codes`: malformed input uses stable `E_*` codes; changed source evidence uses `E_SOURCE_DRIFT`.
- `authority`: execution, approval, repair, merge, publication, deployment, signing, messaging, credential, and connector values are false.
- `implementation_bounds`: depth 0..16, text/path lengths up to 512, mission identifiers up to 120, read chunks of 64 KiB (1024 bytes per KiB), UTF-8 estimate divisor 4, excerpt split divisor 2, and JSON indentation 2 are fixed implementation constants.

### Requirements (EARS)

- When a valid request and readable stable sources are supplied, the system shall produce a self-hash-verified packet with deterministic source ordering and an explicit estimated-token quality marker `CONTEXT_PACKET_READY`. [R1]
- If a request has unknown fields, invalid bounds, traversal, a symlink, duplicate path, secret-shaped key, or unsupported schema, the system shall refuse with a stable `CONTEXT_REQUEST_REFUSED` code and write no ready packet. [R2]
- If a source contains secret-shaped material, is binary, or has a secret-shaped name, the system shall emit digest and identity metadata only as `CONTEXT_SECRET_DIGEST_ONLY` and shall never expose raw content. [R3]
- If a source changes during reading or after packet creation, packet verification shall return `CONTEXT_DRIFT_BLOCKED` with `E_SOURCE_DRIFT` and no authority. [R4]
- When the normalized request and source identities match an existing valid cache key, the system shall reuse the packet deterministically and mark the returned projection as `CONTEXT_CACHE_HIT` without changing release gates. [R5]
- When status is requested, Mission Control, Graph Ops, MCP, and WebMCP shall return bounded metadata and the claim boundary as `CONTEXT_STATUS_READ_ONLY` without executing or approving work. [R6]

### Acceptance criteria

```gherkin
Scenario: Build a compact packet inside the budget
  Given a valid request and stable UTF-8 sources
  When the owner builds a context packet
  Then selected bytes do not exceed max_tokens multiplied by four
  And token_quality states that the count is an estimate, not provider usage
  And `CONTEXT_PACKET_READY` is emitted

Scenario: Refuse changed evidence
  Given a packet whose source changed after it was built
  When the packet is verified
  Then verification is BLOCKED with `E_SOURCE_DRIFT` and `CONTEXT_DRIFT_BLOCKED`
  And no execution, approval, repair, or release authority is granted

Scenario: Reuse exact context
  Given the same request and unchanged source identities
  When the owner builds the packet twice
  Then the second result reports `CONTEXT_CACHE_HIT` and cache.hit true
  And the cache key is identical

Scenario: Keep sensitive context out of the packet
  Given a binary, secret-shaped, or secret-named source
  When the owner builds a context packet
  Then `CONTEXT_SECRET_DIGEST_ONLY` is emitted without an excerpt

Scenario: Refuse malformed requests
  Given a request with a traversal, unknown field, or invalid budget
  When the owner builds a context packet
  Then `CONTEXT_REQUEST_REFUSED` is returned

Scenario: Expose only read-only status
  Given a cached packet status request
  When Mission Control, Graph Ops, MCP, or WebMCP reads it
  Then `CONTEXT_STATUS_READ_ONLY` is returned
```

## SHOULD - Technical/structural

- API: `factory efficiency pack|verify|status`.
- Data lives beneath `.factory/context-efficiency/` and is content-addressed.
- Public projections remain bounded and omit raw excerpts.

## SHOULD NOT - Non-goals

- Do not claim exact model token usage, guaranteed savings, or provider billing reduction.
- Do not execute source, run tests, call a model/provider, alter a contract, or grant approval.
- Do not replace the existing proof-reuse planner or Mission Control seven-reader timing baseline.
