# Agent Oven infrastructure pattern matrix

Reviewed and implemented July 21, 2026. “Implemented” means the durable control-plane contract, authorization, validation, assembly option, and automated tests exist. Provider network calls remain in the trusted hosted-worker boundary and require production tenant credentials.

## Perplexity patterns

| Source pattern | Agent Oven implementation | Evidence |
|---|---|---|
| One multi-provider contract | Provider routes, per-agent BYOK bindings, cache affinity, normalized usage | `inferenceBindings.ts`, `agentIntelligence.ts` |
| Dynamic and frozen presets | Managed/frozen presets with exact version digest and job pinning | `governedRuntimePresets`, `execution.enqueue` |
| Reasoning and tool budgets | Step/input/output/reasoning ceilings plus hard cost and credit admission | `governedRuntimePresets`, `budget.ts` |
| Clarifying questions and follow-up | Required questions block claim; suspended runs accept answers and digest-bound resume | `runtimeClarifications`, `resumeJob` |
| Visible progress and findings | Plan, gather, sufficiency, synthesize, act, validate, complete events and contradiction markers | `runtimeProgressEvents`, `runtimeFindings` |
| Editable durable output | Opaque object reference, digest, media type, editability flag | `runtimeArtifacts` |
| Exact usage | Provider/model, cached/input/output/reasoning tokens, provider cost, latency, tool steps | `runtimeUsageRecords` |
| Structured search filters | Allow/deny domains, recency, date range, country, region, city, coordinates, radius | `governedRuntimePresets` |
| Iterative research/control loop | Typed progress plus sequential, parallel, branch, bounded-loop primitives | `agentIntelligence.ts`, `blueprints.ts` |
| DRACO component evaluation | Ten independent retrieval, quality, connector, and compliance scores | `runtimeComponentScores` |
| Citation/source provenance | Finding source reference and content digest | `runtimeFindings` |

## Mastra Agent Builder patterns

| Source pattern | Agent Oven implementation | Evidence |
|---|---|---|
| Safe primitives for nontechnical builders | Published model/tool/workflow allowlists; guided defaults; progressive advanced controls | `GovernedRuntimePanel.tsx` |
| Model/UI governance | Exact allowlists, frozen/managed channel, RBAC draft/publish lifecycle | `agentIntelligence.ts` |
| Sequential/parallel/branch/loop | Typed flow, dependency validation, bounded iterations | `blueprints.ts` |
| Durable suspend/resume | Executed path, current step, output refs, reason, exact resume digest | `runtimeSnapshots` |
| Trace and scorers | Progress/findings, exact usage, component scores, sanitized run query | `runIntelligence` |
| Sensitive-data filtering | Secrets, tokens, emails, phones redacted; credential-bearing refs rejected | `agentIntelligenceDomain.ts` |
| Own storage and publishing | Convex policy state; nothing self-publishes; every public route is role-guarded | route authorization manifest |

## MANTRA compliance pattern

Knowledge Wall guidance can become a draft symbolic rule with one bounded predicate: required-before, forbidden-after, requires-human-gate, or max-count. A human admin must publish it. The worker evaluates the actual trace deterministically and records exact violated rule IDs. Agent Oven does not claim SMT equivalence; it adopts the machine-checkable manual-to-trace contract without pretending the bounded implementation proves arbitrary policy consistency.

## Remote database operations

The assembler supports PostgreSQL, MySQL, SQL Server, MongoDB, and warehouses through opaque endpoint and secret references. Agents use only human-published views, parameterized operations, or stored procedures. Arbitrary SQL is excluded. Reads queue to the hosted adapter. Writes bind the parameter digest, require a distinct reviewer, and remain incomplete until the adapter returns a result digest.

## Primary sources

- https://docs.perplexity.ai/docs/agent-api/quickstart
- https://docs.perplexity.ai/docs/agent-api/presets
- https://www.perplexity.ai/help-center/en/articles/13600190-what-s-new-in-advanced-deep-research
- https://docs.perplexity.ai/docs/agent-api/filters/domain-filters
- https://r2cdn.perplexity.ai/pplx-draco.pdf
- https://mastra.ai/workshops/mastra-agent-builder-build-agents-no-code-required-2026-06-04
- https://mastra.ai/ai-workflows
- https://mastra.ai/ai-agent-observability
- https://arxiv.org/abs/2605.06334
