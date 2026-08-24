# Spec: code-factory-agent-contract-v2
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core
### Description
This feature closes the gap between the strategy paper's Core-4 agent
customization model and the executable Code Factory. It adds a canonical
Core-5 manifest (Context, Model, Prompt, Tool, Harness), makes UI scope insert
the Prestige gate into the real assembly chain, reconciles all factory receipt
stores into one privacy-safe inventory, and rejects provider routes whose
declared budget or capability contract cannot be satisfied.

### User roles
- Factory operator: creates and validates agent contracts and routes.
- Reviewer: inspects deterministic manifests, receipts, and gate decisions.
- External runtime: supplies credentials and performs provider calls only after
  the factory route is authorized; it cannot alter the sealed decision.

### Requirements (EARS)
- The system shall return marker `AGENT_CONTRACT_BOUND` after validating a Core-5 manifest with role, context, model, prompt, tool, harness, and handoff fields.
- When UI scope is true, the system shall return marker `UI_PRESTIGE_GATE_BOUND` with a plan containing `prestige:score` between smoke and compile.
- When telemetry is queried, the system shall return marker `TELEMETRY_INVENTORY_RECONCILED` with one inventory excluding prompts and receipt bodies.
- When routing is requested, the system shall return marker `PROVIDER_ROUTE_RAILS_ENFORCED` after rejecting a candidate above 12000 tokens, 0.50 USD, or 5000 ms.
- When an external verifier adapter is used, the system shall return marker `VERIFIER_ADAPTER_ATTESTED` after accepting a signed identity and context attestation.
- If a required contract, gate, source, or attestation is stale, the system shall return marker `CONTRACT_GATE_FAIL_CLOSED` with a machine-readable failure and next action.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Core-5 contracts are deterministic and hash-bound
  Given a manifest with valid Context, Model, Prompt, Tool, Harness, and handoff sections
  When the contract validator runs
  Then it returns valid=true with a canonical digest and rejects unknown or missing fields

Scenario: UI assembly cannot bypass Prestige
  Given a feature whose changed paths include a supported UI surface
  When the default assembly chain is planned
  Then prestige:score appears after forgeline:smoke and before hsf:compile

Scenario: Telemetry has one reconciled population
  Given factory receipts in receipts/, .factory/runs/, traces/, and .factory/meter.jsonl
  When the telemetry inventory runs
  Then each source is classified as exact, estimated, or unknown and the run count is derived from one deduplicated run index

Scenario: Provider routing enforces the declared execution contract
  Given a route request with projected tokens, maximum cost, latency, capabilities, and privacy class
  When no candidate satisfies every constraint
  Then routing returns PROVIDER_ROUTE_RAILS_ENFORCED

Scenario: External creator-verifier adapters are accountable
  Given a completion manifest with creator and verifier identities
  When the adapter attestation is absent, mismatched, or includes forbidden creator context
  Then mission completion is rejected and no completion receipt is written

Scenario: Every requirement has an observable factory marker
  Given the Core-5 and release contract
  When strict validator mutation runs
  Then contract markers include `AGENT_CONTRACT_BOUND`, `UI_PRESTIGE_GATE_BOUND`, `TELEMETRY_INVENTORY_RECONCILED`, `PROVIDER_ROUTE_RAILS_ENFORCED`, `VERIFIER_ADAPTER_ATTESTED`, and `CONTRACT_GATE_FAIL_CLOSED`
```

## SHOULD - Technical/structural
- ADR references: the installed Code Factory receipt v2 and provider policy v1
  remain backward compatible; this feature adds versioned envelopes rather than
  mutating legacy receipts.
- Data model: `factory.agent-contract.v2`, `factory.telemetry-inventory.v1`,
  and `factory.provider-route.v2` are canonical JSON envelopes with digest
  bindings and explicit quality markers. Declared decision facts are
  `core5_valid`, `ui_scoped`, `telemetry_conflict`, `route_within_rails`,
  `attestation_valid`, and `all_gates_pass`.
- API contract: Python interfaces in `factoryline.agent_contract`,
  `factoryline.telemetry`, and `factoryline.provider_router`; CLI surfaces are
  `factory agent contract validate`, `factory telemetry inventory`, and
  `factory provider route`.

## SHOULD NOT - Implementation details
Implementation must preserve secret-free policies, external spend authority,
legacy receipt readability, and the existing human-controlled publication and
deployment boundaries.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | `core5_valid == false` | return `AGENT_CONTRACT_INVALID` |
| 2 | `ui_scoped == true` | return an assembly plan containing `prestige:score` |
| 3 | `telemetry_conflict == true` | return reconciliation quality `unknown` |
| 4 | `route_within_rails == false` | return `PROVIDER_ROUTE_RAILS_ENFORCED` |
| 5 | `all_gates_pass == true` and `attestation_valid == true` | return `READY_FOR_EXTERNAL_EXECUTION` |
