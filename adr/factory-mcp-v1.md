# ADR: Factory MCP v1 is a local inspection adapter

## Status

Accepted for `mcp-mermaid-v1`.

## Context

Code Factory already has deterministic Graph Ops facts, a loopback Studio, and
a generated MCP target. Agents still need a compact way to consume the actual
proof graph instead of inferring delivery state from raw repository text.

## Decision

Ship `factory mcp serve --root ROOT` as newline-delimited JSON-RPC over stdio.
It exposes status, Graph Ops, graph impact, and next action only. It has no
remote transport, secrets, connector grant, process execution, or external
effect. Tool and resource calls use the native Graph Ops functions directly.

Generated target and app-builder outputs receive a deterministic Mermaid output
map. It is an inventory and proof-boundary aid, not a completeness certificate.

## Consequences

Agents can obtain exact local state with less context and no second authority
model. New writes or side effects remain in existing CLI/Studio flows behind
their own human-controlled or supervised boundaries. Remote MCP transport and
execution tools require a future, separately reviewed capability contract.
