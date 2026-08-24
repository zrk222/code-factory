# Agent Oven and the 2026 agent economy

Research date: 2026-08-24. Sources are current official protocol, platform, payment-network, and marketplace documentation. This is product architecture research, not legal, tax, payments, or securities advice.

## The opening

The emerging stack is becoming modular:

1. **MCP** connects an agent to tools and data. Its current authorization guidance requires audience-bound tokens and forbids token passthrough.
2. **A2A** lets agents publish Agent Cards and collaborate through task lifecycles.
3. **AP2** carries typed intent and payment mandates so machine spending can remain bound to human-approved limits.
4. **MPP and x402** let machines pay HTTP services programmatically.
5. **Agent marketplaces** make prebuilt agents discoverable, purchasable, and deployable.

These layers describe who can call whom, what can be bought, and how value can move. They do not independently prove that a purchased agent delivered the promised business result. Agent Oven should own that missing layer: an immutable outcome contract, exact proof obligations, an independent deterministic verdict, and conditional release of an authorized result price.

## Official evidence

- [A2A specification](https://a2a-protocol.org/latest/) defines Agent Cards and agent-to-agent task interoperability.
- [MCP 2026-07-28 release](https://blog.modelcontextprotocol.io/posts/2026-07-28/) moves the core to stateless HTTP, adds routable headers and cacheable catalogs, and hardens authorization.
- [MCP authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) requires protected-resource discovery, token audience validation, PKCE, and no token passthrough.
- [Google's agent protocol guide](https://developers.googleblog.com/en/developers-guide-to-ai-agent-protocols/) distinguishes MCP, A2A, commerce, and AP2 payment mandates.
- [Stripe MPP](https://stripe.com/blog/machine-payments-protocol) enables agents to pay HTTP, API, and MCP services through machine-native payment requests.
- [x402 documentation](https://docs.x402.org/introduction) uses HTTP 402 for accountless programmatic payment and supports machine-to-machine usage.
- [Stripe Connect marketplace charges](https://docs.stripe.com/connect/charges) documents destination charges and separate charges/transfers, including the platform's refund and dispute responsibilities.
- [Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/) provides agent identities, sponsors, lifecycle governance, and conditional access.
- [AWS Marketplace AI agents](https://aws.amazon.com/marketplace/solutions/ai-agents-and-tools) offers prebuilt agents, tools, deployment, procurement, and usage/contract pricing.
- [Salesforce AgentExchange](https://www.salesforce.com/news/press-releases/2025/03/04/agentexchange-announcement/) offers prebuilt actions, topics, and templates inside Agentforce.
- [Visa Intelligent Commerce](https://www.visa.com/en-us/solutions/intelligent-commerce) emphasizes agent credentials, spend controls, authentication, and consumer visibility.
- [Google UCP](https://developers.googleblog.com/under-the-hood-universal-commerce-protocol-ucp/) standardizes agent commerce and is designed to work through API, A2A, and MCP surfaces with AP2-compatible payment authorization.

## Product conclusions

### 1. Sell a result contract, not an agent-shaped subscription

Every offer needs a deliverable, acceptance checklist, evidence format, price, expiry, authority boundary, and dispute route. Vague promises such as "improve support" are not payable outcomes. A bounded offer such as "produce a source-linked triage packet for one ticket and pass the four stated checks" can be verified.

### 2. Build for two buyers

- Humans need plain-language outcomes, transparent prices, confirmation, supervision, and a dispute/cancel control.
- Agents need deterministic discovery, JSON schemas, idempotency, mandates, bounded delegation, status reads, and receipts.

Both surfaces must operate the same server-owned contract rather than diverging into a human UI and an ungoverned machine back door.

### 3. Outcome verification is the moat

The seller cannot grade its own work. An exact required-check set, hash-bound artifacts, an independent reviewer identity, and fail-closed state transitions are more defensible than a generic LLM score. Model critique may explain a result, but it cannot release payment.

### 4. Start with internal credits; activate money only through a real rail

The product can prove result pricing today using atomic platform-credit reservations. Real-money activation requires provider onboarding, KYC/KYB, tax and payout decisions, refund/dispute handling, webhook verification, regional availability, and legal terms. Internal reservations must not be marketed as escrow.

### 5. Prebuilt agents must have low-ambiguity outcomes

The first six offers target artifacts that can be inspected without giving the agent unilateral consequential authority:

1. PR Evidence Auditor - verified pull-request proof packet.
2. Security Questionnaire Agent - source-linked response packet for human approval.
3. Support Resolution Agent - policy-grounded response and resolution evidence, not autonomous refunds.
4. Data Quality Reconciler - accepted discrepancy and remediation packet, not silent database writes.
5. Invoice Exception Triage - categorized exception packet, not payment execution.
6. Compliance Evidence Monitor - source-linked change/gap packet, not a compliance certification.

### 6. Non-negotiable controls

- authenticated agent identity with a human sponsor;
- exact resource audience and no token passthrough;
- idempotency and replay resistance;
- one-hop delegation limit and separate sub-budget;
- short expiry and kill switch;
- immutable price, authority, and proof obligations after hire;
- evidence quarantine and prompt-injection treatment for untrusted artifacts;
- deterministic payout gate and independent reviewer;
- explicit `setup-required` status for unverified external rails.

## Commercial path

- **Now:** free catalog discovery and sandbox/internal-credit result contracts.
- **Pilot:** platform fee on verified results, after one regulated payment provider is integrated and audited.
- **Teams:** private offer catalogs, approved-agent allowlists, pooled budgets, SSO/SCIM, audit export, and SLA controls.
- **Enterprise:** private deployment, identity-provider agent sponsorship, policy packs, regional controls, dispute operations, and signed evidence retention.

No revenue, savings, success-rate, or adoption claim should be published until Agent Oven has provider and customer receipts.

## Runtime cooperation: LangGraph and Mastra

The runtime market does not require Agent Oven to pick a single framework:

- LangGraph's current Graph and Functional APIs emphasize explicit or code-shaped control flow, checkpoint persistence, interrupts, retries, replay, and durable human-in-the-loop execution. These are the right primitives for long-running or state-sensitive jobs.
- Mastra's current product emphasizes TypeScript agents, typed tools, workflows, workspaces and sandboxes, MCP exposure, versioned editing, and a governed Agent Builder. These are strong primitives for JavaScript teams and integration-heavy internal agents.
- Both frameworks already build and execute capable agents. Agent Oven's differentiator is the portable intent, policy, evidence, budget, independent-verification, and result-settlement layer around them.

The resulting UX is a form-agent hybrid: one plain-language brief, visible missing questions, a recommended or explicit runtime, a graph preview, model access choice (managed route or BYOK), and a proof contract. A save produces a draft; adapter validation and human activation remain mandatory.

Primary sources:

- https://docs.langchain.com/oss/javascript/langgraph/workflows-agents
- https://docs.langchain.com/oss/javascript/langgraph/persistence
- https://docs.langchain.com/oss/javascript/langgraph/functional-api
- https://mastra.ai/blog/announcing-agent-builder
- https://mastra.ai/docs/agents/mcp-guide
- https://mastra.ai/blog/introducing-mastra-workspaces
- https://mastra.ai/en/reference/workflows/snapshots
