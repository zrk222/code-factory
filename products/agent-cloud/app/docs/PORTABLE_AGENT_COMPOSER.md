# Portable Agent Composer

## Product decision

Agent Oven compiles one detailed outcome brief into a provider-neutral Agent Blueprint. The user can accept the recommended runtime or explicitly choose Agent Oven native, LangGraph, or Mastra. The runtime executes; Agent Oven remains responsible for identity, budget admission, authority, human gates, evidence, memory policy, and result settlement.

## Best-fit runtime choices

| Runtime | Best fit | Native strength retained | Activation boundary |
|---|---|---|---|
| Agent Oven native | Small bounded hosted workflows | Lowest setup cost; native jobs and receipts | Hosted worker and provider route must be configured |
| LangGraph | Explicit state, checkpoints, interrupts, replay, long-running graphs | Durable graph semantics | A deployment-specific adapter must pass reachability and digest validation |
| Mastra | TypeScript agents, tools, workflows, workspaces, and MCP | Ecosystem composition and team tooling | A deployment-specific Mastra adapter must pass reachability and digest validation |

## UX contract

1. The builder treats every user as a novice: one plain-English field, three optional examples, and no runtime jargon in the primary path.
2. Automatic runtime selection and Agent Oven-managed inference are the default; LangGraph, Mastra, and BYOK choices stay behind progressive disclosure.
3. The user describes the observable result, permitted systems, authority, failure rules, and definition of done in ordinary language.
4. The deterministic compiler emits a plain-language summary, visual steps, human gates, evidence checks, and missing questions.
5. Vague intent starts a small guided interview. The user answers each missing decision inline and rebuilds the plan without learning a schema.
6. A ready compilation can be saved as an immutable blueprint version.
7. Saving is not activation. Simulation, connector readiness, runtime reachability, inference access, platform credits, and human activation remain separate gates.

### Always-visible user summary

After compilation the builder keeps four facts understandable without opening an advanced panel:

- what the agent will do;
- what approved knowledge the agent may use;
- where a person must approve or intervene;
- what evidence must exist before success may be reported.

## Model access

- **Agent Oven-managed API:** uses a deployment-configured provider route and normalized usage ledger. It is not active merely because the UI option exists.
- **BYOK:** binds an opaque server-side secret reference through the existing inference-binding boundary. Raw keys never enter composition drafts, blueprints, browser storage, or receipts.

## Privacy and proof boundary

The raw description is used transiently for compilation and is not persisted in `agentCompositionDrafts`. The control plane stores its digest, compiled graph, questions, authority, evidence checks, selected runtime, and compiler digest. The v1 compiler is deterministic and makes no model call. A future model-assisted compiler must produce schema-valid candidates and may not decide activation or weaken required evidence.

## Primary design sources

- LangGraph workflows and agents: https://docs.langchain.com/oss/javascript/langgraph/workflows-agents
- LangGraph persistence: https://docs.langchain.com/oss/javascript/langgraph/persistence
- LangGraph Functional API: https://docs.langchain.com/oss/javascript/langgraph/functional-api
- Mastra Agent Builder: https://mastra.ai/blog/announcing-agent-builder
- Mastra tools and MCP: https://mastra.ai/docs/agents/mcp-guide
- Mastra Workspaces: https://mastra.ai/blog/introducing-mastra-workspaces
- Mastra workflow snapshots: https://mastra.ai/en/reference/workflows/snapshots
