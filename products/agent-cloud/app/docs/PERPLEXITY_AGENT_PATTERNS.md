# Perplexity agent-infrastructure patterns for Agent Oven

Reviewed and implemented July 21, 2026 from Perplexity's official API documentation, product documentation, technical announcement, and DRACO research paper. Exact repository evidence is mapped in `AGENT_INFRA_PATTERN_MATRIX.md`.

## Patterns worth adopting

### Presets with stable operating bands

Perplexity's Agent API bundles model, search, tools, prompts, and maximum steps into named presets. Dynamic presets improve while targeting a stable cost and latency band; frozen configurations support regulated or change-managed workloads. Agent Oven should use the same product abstraction: novices choose a business recipe, while activation seals the exact blueprint version, provider policy, tools, validators, and credit quote. Upgrades remain explicit.

Primary source: https://docs.perplexity.ai/docs/agent-api/presets

### One multi-provider contract with transparent usage

Perplexity normalizes third-party models through one response contract and returns token counts and direct request cost. Agent Oven already normalizes provider bindings and separates platform credits from BYOK inference; the production worker should return provider, model, cached/input/output/reasoning tokens, provider cost, latency, and tool steps through one adapter result. UI must explain both ledgers.

Primary sources: https://docs.perplexity.ai/docs/agent-api/quickstart and https://docs.perplexity.ai/docs/agent-api/models

### Clarify, show progress, expose findings

Advanced Deep Research asks clarifying questions, permits follow-ups while running, shows source-reading progress, surfaces findings before completion, and streams the result into an editable artifact. Agent Oven recipes should ask business questions before activation and expose a stage timeline, intermediate decisions, blockers, and a durable outcome artifact. Booked Job Concierge implements this as profile clarification, scored-decision reasons, approval progress, and append-only outcome events.

Primary source: https://www.perplexity.ai/help-center/en/articles/13600190-what-s-new-in-advanced-deep-research

### Plan, gather, assess sufficiency, then act

Perplexity describes Deep Research as iterative: plan, search, read, decide what is missing, note contradictions, and synthesize only when evidence is sufficient. Agent Oven should generalize the state machine without forcing every recipe into research. For booking: collect declared business facts, score deterministically, expose insufficiency or mismatch, require the exact human approval, then act.

Primary source: https://www.perplexity.ai/hub/blog/deep-research-now-in-computer

### Local and source filters are first-class tools

Perplexity exposes allow/deny domains, recency, dates, country, region, city, and coordinates as structured filters. Agent Oven connectors and recipes should model filters as typed policy—not prompt prose. Booked Job Concierge starts with explicit service and service-area match facts; production adapters can later add geocoded polygons without changing the approval contract.

Primary source: https://docs.perplexity.ai/docs/agent-api/filters/domain-filters

### Component-level, real-task evaluation

DRACO evaluates factual accuracy, completeness, presentation/objectivity, and citation quality with task-specific rubrics derived from de-identified real usage. It explicitly recommends component evaluation for retrieval, source selection, planning, and synthesis. Agent Oven should score each recipe lane independently: intake accuracy, qualification precision, approval integrity, connector reliability, booking completion, attendance, and observed value. Aggregate success must never hide a failed component.

Primary source: https://r2cdn.perplexity.ai/pplx-draco.pdf

## Product boundary

- Research recipes may gather in parallel; bounded operational recipes keep smaller ceilings.
- Citations complement but never substitute for deterministic consent, approval, and operations-rule evidence.
- Managed presets are opt-in; frozen is the default for regulated work.
- Large payloads, prompts, completions, and provider responses remain outside Convex behind opaque references and digests.

## Resulting Agent Oven contract

`business clarification -> frozen recipe version -> typed evidence gathering -> visible progress -> sufficiency/qualification decision -> human gate -> bounded action -> modeled outcome -> observed outcome`
