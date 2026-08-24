# Spec: agent-oven-runtime-adapters-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Agent Oven shall remain the policy, budget, approval, and evidence control plane while delegating admitted execution to a selected runtime engine. Mastra shall use a native HTTP adapter. LangGraph, OpenAI Agents SDK, Microsoft Agent Framework, and Google ADK shall use the versioned Agent Oven Execution Bridge contract until a native adapter is promoted.

### User roles

- Workspace admins configure or disable one runtime adapter per agent using opaque endpoint and secret references.
- Workspace operators select an active adapter by activating its agent blueprint and enqueue digest-bound jobs.
- Trusted workers resolve references, claim admitted work, call the configured engine, and return only bounded runtime evidence.

### Requirements (EARS)

- The system shall return `RUNTIME_ENGINE_REGISTRY` containing exactly `mastra`, `langgraph`, `openai-agents`, `microsoft-agent-framework`, and `google-adk`.
- The system shall return one `RUNTIME_CAPABILITY_MANIFEST` per runtime engine with `transport`, `streaming`, `suspendResume`, `multiAgent`, `traces`, and `nativeAdapter` fields.
- When an admin submits `RUNTIME_ADAPTER_CONFIGURATION`, the system shall store an opaque `env:` or `vault:` endpoint reference, an optional opaque `env:` or `vault:` secret reference, a target identifier, and a declared environment.
- If an endpoint or secret reference contains a raw URL, credential, token, password, query secret, or whitespace, the system shall reject it before persistence with `E_RUNTIME_ADAPTER_REFERENCE_FORBIDDEN`.
- When an adapter is saved, the system shall persist a canonical configuration digest and return `RUNTIME_ADAPTER_CONFIGURED` without resolving either reference.
- When a trusted worker claims a pinned job, the system shall create exactly one idempotent dispatch record and return `RUNTIME_DISPATCH_PREPARED` with a `agent-oven.dispatch.v1` contract containing no raw credential.
- If the current adapter digest differs from the digest pinned to the job, claim shall fail with `E_RUNTIME_ADAPTER_DIGEST_MISMATCH` before external execution.
- When the Mastra worker adapter runs, it shall select `MASTRA_NATIVE_ROUTE` at `POST /api/agents/:targetId/generate` with an idempotency key, dispatch digest, and timeout of 30 seconds.
- When any other supported engine runs, it shall select `AGENT_OVEN_BRIDGE_ROUTE` at `POST /v1/agent-oven/runs` using the same versioned dispatch contract.
- If a resolved endpoint is not HTTPS or loopback HTTP, the worker adapter shall reject it with `E_RUNTIME_ENDPOINT_UNSAFE`.
- If a runtime response omits a non-empty external run identifier, status, or result digest, the worker adapter shall reject it with `E_RUNTIME_RESPONSE_INVALID`.
- The system shall label native versus bridge transport in the operator UI and shall show `RUNTIME_VALIDATION_REQUIRED` as `Configuration saved; worker validation required` until `runtimeAdapter.lastValidatedAt` contains a trusted-worker timestamp.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Mastra dispatch remains governed by Agent Oven
  Given an active blueprint, ready inference binding, sufficient credits, and a ready Mastra adapter
  When an operator enqueues and a trusted worker claims one job
  Then the executionJob stores the Mastra configuration digest
  And the worker receives one credential-free agent-oven.dispatch.v1 contract
  And the native adapter route equals /api/agents/:targetId/generate

Scenario: Additional engines use the common bridge
  Given one supported non-Mastra engine profile
  When a worker builds its request
  Then the request route equals /v1/agent-oven/runs
  And the request carries the same dispatch digest and idempotency key

Scenario: Configuration drift fails closed
  Given a queued job pinned to adapter digest A
  When an admin changes the adapter to digest B before claim
  Then claim returns E_RUNTIME_ADAPTER_DIGEST_MISMATCH
  And no dispatch record is created

Scenario: Raw credentials never enter Convex
  Given a runtime adapter form
  When an admin submits a URL or raw bearer token instead of an opaque reference
  Then E_RUNTIME_ADAPTER_REFERENCE_FORBIDDEN is returned
  And no adapter configuration is persisted
```

## SHOULD - Technical and structural

- Keep runtime transport code outside Convex; Convex stores governance and dispatch state only.
- Keep the execution bridge payload stable across engine implementations.
- Treat adapter support as `supervised` until a live worker receipt proves endpoint reachability and response validation.
- Preserve existing native Agent Oven test jobs when no external adapter is configured.

## SHOULD NOT - Implementation details

- Do not store resolved endpoints, bearer values, prompts, completions, or provider credentials in Convex.
- Do not let an adapter reserve credits, authorize tools, approve actions, or alter a blueprint.
- Do not describe bridge compatibility as a vendor-certified integration.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `RUNTIME_ENGINE_REGISTRY` | return five declared engine identifiers |
| 2 | `RUNTIME_CAPABILITY_MANIFEST` | return six capability fields |
| 3 | `RUNTIME_ADAPTER_CONFIGURATION` | store opaque references and declared target |
| 4 | `RUNTIME_ADAPTER_CONFIGURED` | store canonical digest |
| 5 | `RUNTIME_DISPATCH_PREPARED` | store one dispatch record |
| 6 | `MASTRA_NATIVE_ROUTE` | route to `/api/agents/:targetId/generate` |
| 7 | `AGENT_OVEN_BRIDGE_ROUTE` | route to `/v1/agent-oven/runs` |
| 8 | `E_RUNTIME_ENDPOINT_UNSAFE` | reject external request |
| 9 | `E_RUNTIME_RESPONSE_INVALID` | reject runtime result |
| 10 | `RUNTIME_VALIDATION_REQUIRED` | display worker validation requirement |
