# Spec: receipt-graph-runtime
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Code Factory shall expose each governed Product Mission as a durable stateful
graph. The graph shall make approval, worker, independent-validation,
correction, completion, release-decision, and outcome states inspectable and
resumable without granting an orchestration framework authority to validate
evidence or perform external effects. A stdlib SQLite event store is the
canonical runtime record. An optional LangGraph adapter may mirror valid
transitions into durable LangGraph checkpoints for teams that use LangGraph.

### User roles

- Mission owner: approves, defers, or rejects bounded execution and records release decisions.
- Worker: records a candidate-ready handoff but cannot validate or promote it.
- Independent validator: records pass/fail evidence and cannot be the worker.
- Operator: inspects health, state, history, Mermaid topology, and dependency readiness.

### Requirements (EARS)

- The system shall return marker `MISSION_GRAPH_INITIALIZED` after binding a verified `factory.mission.v1` artifact to a transactional SQLite thread.
- The system shall return marker `MISSION_GRAPH_HASH_CHAIN_BOUND` after every accepted transition stores the previous event hash, canonical event hash, mission hash, actor, role, idempotency key, and receipt hash.
- When the same idempotency key and identical event are submitted twice, the system shall return marker `MISSION_GRAPH_IDEMPOTENT` without advancing the version twice.
- If an idempotency key is reused with different event bytes, the system shall reject the event with `MISSION_GRAPH_IDEMPOTENCY_CONFLICT`.
- The system shall return marker `MISSION_GRAPH_TRANSITION_GUARDED` when only declared source-state, event, role, and receipt combinations may advance the graph.
- The system shall return marker `MISSION_GRAPH_MILESTONES_BOUND` after exposing every mission completion criterion and falsifiable hypothesis as one pending principal milestone.
- When execution is approved, deferred, or rejected, the system shall return marker `MISSION_GRAPH_OWNER_DECISION_BOUND` or reject the transition unless a verified owner-bound `factory.mission.decision.v1` receipt is supplied.
- When a candidate is ready, the system shall return marker `MISSION_GRAPH_CANDIDATE_BOUND` after requiring the worker role and a hash-bound local candidate receipt beneath the configured repository root.
- When verification passes, the system shall return marker `MISSION_GRAPH_COMPLETION_BOUND` or reject the transition unless a valid `factory.mission.completion.v1` receipt with distinct creator and verifier identities is supplied.
- When verification fails, the system shall return marker `MISSION_GRAPH_VALIDATION_FAILED_BOUND` after requiring an independent validator, a local evidence receipt, and transitioning to `correction_required`.
- When correction is retried, the system shall increment the attempt count, reject retries above the mission `max_iterations`, and require a fresh worker context.
- When measured usage is recorded, the system shall return marker `MISSION_GRAPH_USAGE_RECEIPT_BOUND` after storing cumulative tokens, cost in USD, and wall seconds from a hash-bound local usage receipt without converting unavailable values to zero.
- If measured cumulative tokens, cost, wall seconds, or iterations reaches the mission maximum, the system shall transition to `budget_exhausted`, return marker `MISSION_GRAPH_BUDGET_ENFORCED`, and reject worker or validation progress events.
- The system shall return marker `MISSION_GRAPH_USAGE_MEASURED` after distinguishing measured provider usage from modeled estimates and unknown values.
- When a route recommendation is requested, the system shall return marker `MISSION_GRAPH_ROUTING_EXPLAINED` with an abstract economy, balanced, or frontier tier derived from declared risk, failed attempts, remaining budget ratio, cache continuity, and required quality floor.
- When owner execution approval is evaluated, the system shall return marker `MISSION_GRAPH_READINESS_GATED` after reporting whether tests, lint or static analysis, and acceptance validators are declared; missing readiness evidence shall require human-controlled rather than autonomous operation.
- When the mission owner interrupts creator or validation work, the system shall return marker `MISSION_GRAPH_HUMAN_INTERRUPT` after transitioning to `paused_for_review` without consuming another iteration.
- When a paused mission is redirected, the system shall return marker `MISSION_GRAPH_PLAN_REVISION_BOUND` after binding one local revised plan or spec receipt and requiring a fresh worker context before resuming.
- When repository context is refreshed, the system shall return marker `MISSION_GRAPH_CONTEXT_REFRESH_BOUND` after binding current AutoWiki, Lore, and storyboard receipt hashes without storing agent scratchpads.
- The system shall return marker `MISSION_GRAPH_RELEASE_AUTHORITY_SEPARATE` because release-decision transitions record exactly one human decision and perform zero merge, publish, deploy, message, credential, connector, or production-write operations.
- The system shall return marker `MISSION_GRAPH_RESUMABLE` when closing and reopening the store preserves the exact state, version, attempt count, and event chain.
- If any stored event, receipt hash, previous hash, or mission binding drifts, the system shall return marker `MISSION_GRAPH_DRIFT` and refuse further transitions.
- The system shall return marker `MISSION_GRAPH_MERMAID_EXPORTED` after rendering the declared topology and current state without executing the graph.
- The system shall return exactly one LangGraph availability marker: `LANGGRAPH_ADAPTER_BOUND` after compiling a checkpointed adapter through the Code Factory validator, or `LANGGRAPH_OPTIONAL_FALLBACK` while native commands continue and one installation command is reported.
- The system shall return marker `LANGGRAPH_CHECKPOINT_SECONDARY` because LangGraph checkpoints are resumability aids and never replace the canonical Code Factory event/receipt chain.
- The system shall return marker `LANGGRAPH_OPERATOR_COMMANDS` after emitting JSON from the six `factory langgraph` operator commands.
- The system shall return marker `PROVIDER_POLICY_SECRET_FREE` after storing only provider IDs, model IDs, price metadata, IDE selections, routing rails, and environment-variable names while storing zero credential values.
- The system shall return marker `PROVIDER_POLICY_VERIFIED` after canonical hash verification and rejection of unknown fields, duplicate IDs, invalid tiers, non-HTTPS remote endpoints, and out-of-range numeric rails.
- When a user selects CLI, Studio, VS Code, or JetBrains, the system shall return marker `PROVIDER_IDE_SELECTED` or reject routing unless the selected surface is policy-allowed.
- When a provider route is requested, the system shall return marker `PROVIDER_ROUTE_EXPLAINED` with the selected provider/model, abstract tier, price facts, credential-presence boolean, and deterministic reasons.
- If a preferred provider, model, mission budget, quality floor, or provider allowlist violates policy, the system shall return marker `PROVIDER_ROUTE_RAILS_ENFORCED` and select no route.
- The system shall return marker `PROVIDER_CREDENTIAL_REFERENCE_ONLY` because BYOK keys are read by an external runtime from declared environment-variable names and are never returned, logged, hashed, or written by Code Factory.
- The system shall return marker `PROVIDER_CACHE_AWARE` after preferring an eligible current provider/model when cache continuity is requested and its projected policy cost does not exceed the cheapest eligible route.
- The system shall return marker `PROVIDER_NO_CALL_AUTHORITY` because routing performs zero provider API calls and grants zero spend, credential, deployment, publication, or external-message authority.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Resume an approved mission through correction and completion
  Given a verified mission and approved execution decision
  When an owner approval, worker handoff, failed independent validation, retry, new handoff, and valid completion are recorded
  Then reopening the runtime returns completion_receipted with one retry
  And every transition is hash-linked and independently verifiable

Scenario: Reject replay, role confusion, and forged completion
  Given an initialized mission graph
  When an idempotency key is reused with different input, a worker validates its own work, or completion evidence drifts
  Then the graph rejects the event without changing its state or version

Scenario: Stop at the exact mission budget
  Given measured cumulative usage equal to one mission maximum
  When another worker or validation progress event is requested
  Then the graph is `budget_exhausted` with marker `MISSION_GRAPH_BUDGET_ENFORCED`
  And the progress event is rejected without advancing the version

Scenario: Keep release authority outside the runtime
  Given a completed mission graph
  When the owner records that release review is requested or decided
  Then the graph records the decision and receipt
  And it performs no merge, publish, deploy, message, credential, connector, or production-write action

Scenario: Interrupt and redirect an active mission
  Given an approved mission with a running creator
  When the owner pauses the mission, supplies a revised plan receipt, and resumes it
  Then the runtime preserves the prior event chain and returns to creator_running
  And the next worker context is fresh and binds the revised plan hash

Scenario: Run with and without LangGraph installed
  Given the Code Factory package without optional LangGraph dependencies
  When an operator initializes and advances a native mission graph
  Then durable state and receipts work normally
  And doctor returns marker `LANGGRAPH_OPTIONAL_FALLBACK` with one installation command
  Given the LangGraph extra is installed
  When the same event is invoked through the adapter with one thread id
  Then the adapter returns marker `LANGGRAPH_ADAPTER_BOUND`
  And LangGraph checkpoints the state while Code Factory validates the transition

Scenario: Route across BYOK providers and IDE surfaces without storing keys
  Given a verified provider policy with two provider/model choices and environment-variable key references
  When the user selects JetBrains and requests a route for one verified mission
  Then the route obeys the provider allowlist, mission budget, quality floor, and selected IDE
  And the result contains no credential value and performs no provider call

Scenario: Every graph-runtime requirement has an observable validator marker
  Given the receipt graph runtime contract
  When strict validator mutation runs
  Then contract markers include `MISSION_GRAPH_INITIALIZED`, `MISSION_GRAPH_HASH_CHAIN_BOUND`, `MISSION_GRAPH_IDEMPOTENT`, `MISSION_GRAPH_IDEMPOTENCY_CONFLICT`, `MISSION_GRAPH_TRANSITION_GUARDED`, `MISSION_GRAPH_MILESTONES_BOUND`, `MISSION_GRAPH_OWNER_DECISION_BOUND`, `MISSION_GRAPH_CANDIDATE_BOUND`, `MISSION_GRAPH_COMPLETION_BOUND`, `MISSION_GRAPH_VALIDATION_FAILED_BOUND`, `MISSION_GRAPH_USAGE_RECEIPT_BOUND`, `MISSION_GRAPH_BUDGET_ENFORCED`, `MISSION_GRAPH_USAGE_MEASURED`, `MISSION_GRAPH_ROUTING_EXPLAINED`, `MISSION_GRAPH_READINESS_GATED`, `MISSION_GRAPH_HUMAN_INTERRUPT`, `MISSION_GRAPH_PLAN_REVISION_BOUND`, `MISSION_GRAPH_CONTEXT_REFRESH_BOUND`, `MISSION_GRAPH_RELEASE_AUTHORITY_SEPARATE`, `MISSION_GRAPH_RESUMABLE`, `MISSION_GRAPH_DRIFT`, `MISSION_GRAPH_MERMAID_EXPORTED`, `LANGGRAPH_ADAPTER_BOUND`, `LANGGRAPH_OPTIONAL_FALLBACK`, `LANGGRAPH_CHECKPOINT_SECONDARY`, `LANGGRAPH_OPERATOR_COMMANDS`, `PROVIDER_POLICY_SECRET_FREE`, `PROVIDER_POLICY_VERIFIED`, `PROVIDER_IDE_SELECTED`, `PROVIDER_ROUTE_EXPLAINED`, `PROVIDER_ROUTE_RAILS_ENFORCED`, `PROVIDER_CREDENTIAL_REFERENCE_ONLY`, `PROVIDER_CACHE_AWARE`, and `PROVIDER_NO_CALL_AUTHORITY`
  And transition tests cover owner decisions, candidate receipts, completion receipts, failed validation, bounded retries, dependency absence, and adapter availability
```

## SHOULD - Technical/structural

- ADR reference: `adr/0013-receipt-backed-graph-runtime.md`
- Data models: `factory.mission.graph.v1`, `factory.mission.graph.event.v1`, `factory.mission.graph.verification.v1`
- Canonical storage pattern: `.factory/missions/MISSION_SLUG/mission-graph.sqlite3`
- Exported topology pattern: `.factory/missions/MISSION_SLUG/mission-graph.mmd`
- Optional dependencies: LangGraph version 1.1 or newer but earlier than 2.0, and langgraph-checkpoint-sqlite version 3.0 or newer but earlier than 4.0.
- SQLite transactions use `BEGIN IMMEDIATE`, foreign keys, WAL mode, and unique idempotency keys.
- Event payloads are JSON objects limited to 65536 canonical UTF-8 bytes.
- Actor and idempotency strings are nonempty and limited to 120 characters.
- Local receipt inputs must be files beneath the configured repository root.
- Price control never raises the Product Mission maxima of 5 iterations, 3600 wall seconds, 100000 tokens, or 25 USD; a user may only choose a lower non-negative threshold.
- Route recommendations use abstract tiers and never persist provider credentials or select a concrete paid endpoint.
- Supported IDE selectors are exactly `cli`, `studio`, `vscode`, and `jetbrains`.
- Provider policy routing bias is an integer from 0 through 100; 0 favors price and 100 favors quality, but the quality floor remains hard.
- Provider and model IDs are 1 through 80 characters; environment-variable names are 3 through 80 uppercase characters.
- One policy accepts at most 32 providers and at most 64 models per provider.
- The default quality floor is `balanced` and the default routing bias is 50.
- Provider keys may be referenced only by environment names matching uppercase letters, digits, and underscores with 3 through 80 characters.

## SHOULD NOT - Implementation details

- Do not store model scratchpads, chain-of-thought, credentials, or connector secrets.
- Do not replace AutoWiki, Lore, or storyboard system-of-record artifacts with conversational memory.
- Do not make LangGraph, LangSmith, or a hosted service mandatory for native operation.
- Do not call models, execute workers, run arbitrary commands, or perform external effects from a graph transition.
- Do not accept a LangGraph checkpoint as evidence that a Code Factory transition is valid.
- Do not automatically replay side-effecting nodes.
- Do not accept credentials through command arguments, JSON policy values, IDE settings, or graph payloads.

## Decision logic (factory candidates)

Decision facts: `mission_valid: boolean`, `chain_valid: boolean`,
`idempotency_conflict: boolean`, `transition_valid: boolean`,
`retry_count: integer`, `max_iterations: integer`,
`budget_reached: boolean`, `external_effect_requested: boolean`, and
`langgraph_available: boolean`.

| # | if | then |
|---|----|------|
| 1 | `mission_valid` == false | REJECT_MISSION_GRAPH_INIT |
| 2 | `chain_valid` == false | REPORT_MISSION_GRAPH_DRIFT |
| 3 | `idempotency_conflict` == true | REJECT_EVENT |
| 4 | `transition_valid` == false | REJECT_TRANSITION |
| 5 | `retry_count` > `max_iterations` | REJECT_BUDGET |
| 6 | `budget_reached` == true | STOP_MISSION |
| 7 | `external_effect_requested` == true | RECORD_DECISION_ONLY |
| 8 | `langgraph_available` == false | CONTINUE_NATIVE_AND_REPORT_INSTALL |
| 9 | `langgraph_available` == true | BUILD_LANGGRAPH_ADAPTER |
| 10 | else | WRITE_HASH_LINKED_TRANSITION |
