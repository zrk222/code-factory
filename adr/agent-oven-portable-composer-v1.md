# ADR: Portable Agent Composer v1

## Status

Accepted for the local deployable application. Production provider routes and external runtime endpoints remain setup-required until deployment-specific reachability, authorization, and usage read-backs pass.

## Decision

Agent Oven owns a deterministic intent compiler and governance envelope while execution remains portable. An authorized operator describes the result, systems, authority, and failure rules. The compiler produces explicit steps, human gates, evidence requirements, and one runtime choice: Agent Oven native for bounded hosted workflows, LangGraph for checkpointed stateful graphs, or Mastra for TypeScript-native tools, workspaces, and MCP-heavy agents.

Inference is a separate choice. Agent Oven-managed inference uses a metered deployment route; BYOK uses an opaque server-side secret reference. Neither mode places a raw credential in the browser or blueprint.

Compilation, saving, activation, execution, verification, and settlement are distinct transitions. Missing intent decisions block saving. Missing external-runtime validation blocks simulation and activation. Execution remains governed by the existing inference binding, cost reservation, capability, approval, evidence, and receipt controls.

## Consequences

- Users receive one approachable builder without losing explicit runtime choice.
- LangGraph and Mastra are execution partners, not competing sources of governance truth.
- The same intent produces the same compiler digest.
- Raw briefs and raw credentials are excluded from persisted draft state.
- Agent Oven can add future runtimes behind the same blueprint and adapter contract.
- No runtime, model, or deployment is represented as live without provider-specific evidence.
