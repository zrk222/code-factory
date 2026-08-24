# Spec: agent-oven-portable-composer-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Provide a form-agent hybrid that lets an authorized operator describe an outcome agent in plain language, compile the description into a deterministic and reviewable blueprint, choose Agent Oven native, LangGraph, or Mastra execution, and select Agent Oven-managed inference or BYOK. Compilation creates no running agent and stores no raw description.

### User roles

- Viewer: may inspect runtime compatibility and compiled drafts for an authorized agent.
- Operator: may compile a plain-language brief into a digest-bound draft.
- Admin: may save the draft as a versioned blueprint and later activate it after existing simulation, adapter, inference, budget, and approval gates pass.

### Requirements (EARS)

- The system shall return `AGENT_INTENT_COMPILED` with one selected runtime, one authority policy, one memory policy, ordered workflow steps, acceptance evidence, clarification questions, an intent digest, and a deterministic compiler digest.
- The system shall return Boolean facts `requiresState`, `requiresTooling`, `consequential`, `missingIntentDimension`, `externalRuntimeSelected`, and `externalAdapterReady` from the validated brief and adapter state.
- When a validated brief names TypeScript, MCP, tools, integrations, workspaces, or webhooks, the system shall return `requiresTooling = true`.
- When `runtimePreference = auto`, the system shall return `selectedRuntime = langgraph` for `requiresState = true`, `selectedRuntime = mastra` for `requiresTooling = true`, and `selectedRuntime = agent-oven-native` when both facts are false.
- When an identical normalized brief, runtime preference, and inference choice are compiled more than once, the system shall return the same compiler digest.
- If observable success, permitted sources, action authority, or failure behavior is absent, the system shall return `needs-clarification` and shall not permit the UI to save the draft as a governed blueprint.
- When the compiler returns clarification questions, the UI shall render one plain-language answer field per missing decision and shall recompile the enriched brief only after every answer is present.
- The system shall render runtime and inference controls inside an optional advanced section and shall return `runtimePreference = auto` and `inferenceAccess = agent-oven-api` as initial UI defaults.
- When compilation finishes, the UI shall display a plain-language summary of knowledge use, authority, human control, and success evidence before displaying save.
- When a brief includes a consequential action, the system shall add a human gate and shall compile `approval-required` authority.
- The system shall store the intent digest and compiled controls but shall not store the raw plain-language brief.
- When the user chooses BYOK, the system shall persist only the BYOK mode; credentials shall remain opaque server-side references and shall never enter the browser or blueprint.
- When the user chooses Agent Oven-managed inference, the system shall return the managed inference mode as setup-required until a deployment-specific provider route and usage read-back are verified.
- If a LangGraph or Mastra blueprint lacks a ready adapter for that exact agent and engine, simulation shall report a blocker and activation shall return `E_BLUEPRINT_RUNTIME_ADAPTER_NOT_READY`.
- The system shall present saving, activation, and execution as distinct states and shall not claim deployment from compilation or save success.
- The system shall publish a machine-readable runtime compatibility document with an explicit status for every runtime and inference capability.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Compile a durable graph agent
  Given a detailed brief with checkpoints, approval, sources, success, and failure rules
  When the operator selects best-fit runtime and managed inference
  Then AGENT_INTENT_COMPILED selects LangGraph and returns a ready digest-bound draft

Scenario: Compile a TypeScript integration agent
  Given a detailed brief that requires TypeScript, MCP, tools, and a workspace
  When the operator selects best-fit runtime and BYOK
  Then AGENT_INTENT_COMPILED selects Mastra and stores no raw brief or credential

Scenario: Refuse an underspecified agent
  Given a vague brief without success, sources, authority, or failures
  When the operator compiles it
  Then the result needs clarification and the save action remains disabled

Scenario: Guide a novice through missing decisions
  Given a compilation that needs clarification
  When the user answers every visible question in ordinary language
  Then the builder recompiles the enriched brief and updates the visible plan

Scenario: Block an unvalidated external runtime
  Given a saved LangGraph blueprint without a ready LangGraph adapter
  When an admin simulates or activates the blueprint
  Then simulation reports the exact adapter blocker and activation fails closed
```

## SHOULD - Technical/structural

- ADR reference: `adr/agent-oven-portable-composer-v1.md`.
- Domain compiler: `products/agent-cloud/app/convex/agentComposerDomain.ts`.
- Convex API: `products/agent-cloud/app/convex/agentComposer.ts`.
- UI: `products/agent-cloud/app/src/components/IntentComposer.tsx`.
- Discovery: `products/agent-cloud/app/public/.well-known/runtime-compatibility.json`.

## SHOULD NOT - Implementation details

- No model call is required to decide readiness, runtime selection, authority, or evidence.
- No raw description, provider key, access token, endpoint secret, or deployment credential is stored in a draft.
- No external runtime is represented as ready from configuration alone; worker validation remains required.
- No compiler receipt is represented as proof that the agent completed an outcome.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `missingIntentDimension = true` | return `needs-clarification` and disable save |
| 2 | `runtimePreference = auto` and `requiresState = true` | return `selectedRuntime = langgraph` |
| 3 | `runtimePreference = auto` and `requiresState = false` and `requiresTooling = true` | return `selectedRuntime = mastra` |
| 4 | `runtimePreference = auto` and both runtime facts are false | return `selectedRuntime = agent-oven-native` |
| 5 | `consequential = true` | add a human gate and require approval |
| 6 | `externalRuntimeSelected = true` and `externalAdapterReady = false` | return `E_BLUEPRINT_RUNTIME_ADAPTER_NOT_READY` |
