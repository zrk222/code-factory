# Spec: product-missions
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Code Factory shall compile a UTF-8 PRD into a traceable Product Graph, a
dependency-safe value-slice plan, and a bounded implementation mission. It
shall prepare evidence-linked draft PR material and hash-linked outcome
records without executing an agent, merging code, publishing, deploying, or
sending an external message. The compiler is deterministic and local; agent
runtimes remain replaceable adapters governed by the generated Loop Passport.

### User roles

- Product engineer: supplies the PRD, resolves blocking gaps, and approves slices.
- Builder: implements one approved mission in an isolated branch or worktree.
- Checker: validates requirement, UX, test, security, and architecture evidence.
- Reviewer: owns PR approval, merge, release, and any external side effect.

### Requirements (EARS)

- The system shall return marker `PRODUCT_GRAPH_BOUND` after writing schema
  `factory.product_graph.v1` with the PRD SHA-256 and stable requirement IDs.
- The system shall return marker `REQUIREMENT_ATOMS_STABLE` when unchanged
  requirement text produces the same IDs across repeated compilations.
- When a PRD omits requirements or acceptance evidence, the system shall return marker `PRODUCT_GAPS_EXPOSED` and store status `needs_input` without inventing product behavior.
- When a PRD contains user-facing behavior, the system shall return marker `UX_STATES_AUDITED` with explicit loading, empty, error, success, permission,
  offline, recovery, and accessibility coverage states classified as declared or missing.
- The system shall return markers `PRODUCT_TRUST_MODEL_BOUND` and
  `PRODUCT_OUTCOME_EVENTS_BOUND` after storing explicitly supplied jobs, pains,
  outcomes, journeys, business rules, data ownership, trust boundaries,
  external effects, approval requirements, and success events without inventing omitted facts.
- The system shall return marker `VALUE_SLICES_COVERAGE_COMPLETE` after every
  requirement is assigned exactly once to a vertical slice or explicitly deferred.
- The system shall return markers `VERTICAL_SLICE_CONTRACT_BOUND` and
  `VALUE_SLICE_SCORE_DETERMINISTIC` after storing UI, behavior, API/data, tests,
  observability, rollback, and the deterministic five-factor priority score in every value slice.
- The system shall return marker `DEPENDENCY_ORDER_DETERMINISTIC` when slices
  use only explicit requirement references for dependencies and stable tie-breaking.
- If blocking Product Graph gaps remain, the system shall return marker `MISSION_BLOCKED_BY_PRODUCT_GAPS` and shall not write a mission or Loop Passport.
- When a mission is created, the system shall return marker `MISSION_PASSPORT_BOUND` after writing schema `factory.mission.v1`, a minimal
  context packet, a Loop Manifest, and a verified Loop Passport bound to graph
  and slice hashes.
- The system shall return markers `MISSION_SINGLE_WORKTREE_BOUND`,
  `MISSION_CONTEXT_MINIMIZED`, and `MISSION_ROLE_PERMISSIONS_SEPARATE` after
  storing one branch/worktree, minimal selected-slice context, and separate
  builder, checker, and UX reviewer permissions in each mission.
- The system shall return marker `MISSION_BUDGET_HARD` with maximum values of
  5 iterations, 3600 wall seconds, 100000 tokens, and 25 USD unless the caller
  supplies smaller non-negative values.
- The system shall return markers `MISSION_HYPOTHESES_BOUND`,
  `MISSION_FRESH_CONTEXT_ATTEMPTS`, and `MISSION_MODEL_ROUTING_BOUNDED` after
  binding every falsifiable hypothesis to one completion criterion, forbidding
  prior-attempt context, and selecting only an abstract risk-based model tier
  beneath the unchanged hard mission budget.
- When a value slice has user-facing behavior, the system shall return marker `BROWSER_CONTROL_CRITERION_BOUND` after requiring schema `factory.browser-flow.evidence.v1`, exact expected URL, fewer than 4 interactions, all assertions passing, a distinct verifier, and hash-bound visual evidence.
- When migration readiness is supplied, the system shall return marker `MIGRATION_AGENT_READY_BOUND` only if `lane_registration_pct` and `executable_proof_pct` are both 100 and all eight required proof categories remain hash-valid.
- When repository context exists before mission creation, the system shall return marker `REPOSITORY_CONTEXT_BOUND` after binding tracked-fact AutoWiki, Lore, and planned video-storyboard hashes into the mission.
- The system shall return marker `EXTERNAL_EFFECTS_APPROVAL_REQUIRED` when the
  mission contract requires separate human approval for merge, publish,
  deploy, delete, production write, external messages, credentials, and connectors.
- When one PR draft is created, the system shall return marker `PR_EVIDENCE_LINKED` after storing requirement coverage, acceptance evidence paths, risks, rollback, outcome events, and explicit unproven claims.
- The system shall return markers `PR_REVIEW_PACKAGE_COMPLETE` and
  `PR_UNPROVEN_CLAIMS_EXPLICIT` with a PR packet containing before/after outcome,
  architecture/data changes, screenshots, responsive/accessibility proof, tests,
  mutations, gates, traces, budgets, security, rollout, rollback, and explicit unknowns.
- The system shall return marker `PR_DRAFT_NO_MERGE_AUTHORITY` for every PR
  package generated by this feature.
- When an outcome is recorded, the system shall return marker `OUTCOME_EVIDENCE_CLASSIFIED` with evidence classified as measured,
  observed, modeled, or unknown and linked to the mission hash.
- The system shall return marker `OUTCOME_CHAIN_BOUND` after binding each new
  outcome record to the previous outcome hash.
- When Meter v2 reads legacy rows, the system shall return marker `METER_V2_BACKWARD_COMPATIBLE` and preserve their measured wall time.
- When Meter v2 summarizes mission rows, the system shall return marker `FLOW_EFFICIENCY_MEASURED` with queue, execution, review, rework, cache,
  invalidation, and outcome fields without converting unknown values to zero.
- When Factory Studio compiles a Product Mission, the system shall return marker `STUDIO_PRODUCT_MISSION_CONTAINED` and write only beneath its configured root.
- When VS Code or JetBrains opens Product Missions, the system shall return marker `EDITOR_PRODUCT_MISSION_CONFIRMED` after workspace trust or explicit confirmation.
- If any source hash changes, the system shall return marker `MISSION_INPUT_DRIFT` and set mission validity to `false`.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Compile a PRD into one governed mission
  Given a UTF-8 PRD with roles, requirements, acceptance criteria, and outcomes
  When product compile, product slices, and mission create run in order
  Then every requirement appears in exactly one slice
  And the mission and Loop Passport bind the PRD, graph, and slice hashes
  And promotion and external effects still require a human

Scenario: Expose an incomplete product contract
  Given a PRD with prose but no testable requirement or acceptance evidence
  When product compile runs
  Then the graph status is needs_input with blocking gaps
  And mission create writes no mission or Loop Passport

Scenario: Detect requirement mutation and drift
  Given a compiled graph and mission
  When one requirement is deleted or its source bytes change
  Then graph comparison or mission verification reports an invalidated requirement or MISSION_INPUT_DRIFT

Scenario: Prepare a proof-linked review
  Given a valid mission and local evidence files
  When pr draft runs
  Then the draft lists covered requirements, evidence hashes, risks, rollback, outcome events, and unproven claims
  And the draft grants no merge authority

Scenario: Preserve honest productivity data
  Given legacy meter rows and new mission meter rows
  When factory meter runs
  Then legacy wall time remains readable
  And unavailable token, review, rework, and outcome values remain classified as unknown

Scenario: Preserve the full product engineering contract
  Given a PRD with explicit product, trust, UX, and outcome facts
  When the product mission and reviewer packet are compiled
  Then the Product Graph stores supplied jobs, pains, outcomes, journeys, business rules, ownership, trust boundaries, external effects, approvals, and success events
  And every value slice stores UI, behavior, API/data, tests, observability, rollback, and a deterministic five-factor score
  And each mission stores one branch and worktree, minimal selected-slice context, and separate builder, checker, and UX reviewer permissions
  And the PR packet returns before/after outcome, architecture/data changes, screenshots, responsive/accessibility proof, tests, mutations, gates, traces, budgets, security, rollout, and rollback

Scenario: Refuse migration completion without executable readiness and UI proof
  Given a migration readiness manifest and one user-facing value slice
  When mission creation and independent completion run
  Then registration without executed proof blocks mission creation
  And the completed mission binds every hypothesis to one criterion
  And computer-control evidence must match the expected URL in fewer than 4 interactions with all assertions and visual hashes present

Scenario: Every requirement has an observable validator marker
  Given the Product Missions contract
  When strict validator mutation runs
  Then contract markers include `PRODUCT_GRAPH_BOUND`, `REQUIREMENT_ATOMS_STABLE`, `PRODUCT_GAPS_EXPOSED`, `UX_STATES_AUDITED`, `PRODUCT_TRUST_MODEL_BOUND`, `PRODUCT_OUTCOME_EVENTS_BOUND`, `VALUE_SLICES_COVERAGE_COMPLETE`, `DEPENDENCY_ORDER_DETERMINISTIC`, `VALUE_SLICE_SCORE_DETERMINISTIC`, `VERTICAL_SLICE_CONTRACT_BOUND`, `MISSION_BLOCKED_BY_PRODUCT_GAPS`, `MISSION_PASSPORT_BOUND`, `MISSION_SINGLE_WORKTREE_BOUND`, `MISSION_CONTEXT_MINIMIZED`, `MISSION_ROLE_PERMISSIONS_SEPARATE`, `MISSION_BUDGET_HARD`, `MISSION_HYPOTHESES_BOUND`, `MISSION_FRESH_CONTEXT_ATTEMPTS`, `MISSION_MODEL_ROUTING_BOUNDED`, `BROWSER_CONTROL_CRITERION_BOUND`, `MIGRATION_AGENT_READY_BOUND`, `REPOSITORY_CONTEXT_BOUND`, `EXTERNAL_EFFECTS_APPROVAL_REQUIRED`, `PR_EVIDENCE_LINKED`, `PR_REVIEW_PACKAGE_COMPLETE`, `PR_UNPROVEN_CLAIMS_EXPLICIT`, `PR_DRAFT_NO_MERGE_AUTHORITY`, `OUTCOME_EVIDENCE_CLASSIFIED`, `OUTCOME_CHAIN_BOUND`, `METER_V2_BACKWARD_COMPATIBLE`, `FLOW_EFFICIENCY_MEASURED`, `STUDIO_PRODUCT_MISSION_CONTAINED`, `EDITOR_PRODUCT_MISSION_CONFIRMED`, and `MISSION_INPUT_DRIFT`
```

## SHOULD - Technical and structural

- ADR references: `adr/0008-product-missions-value-compiler.md`
- Data models: `factory.product_graph.v1`, `factory.value_slices.v1`,
  `factory.mission.v1`, `factory.pr_draft.v1`, `factory.outcome.v1`,
  `factory.meter.live.v2`, `factory.migration.readiness.v1`,
  `factory.browser-flow.evidence.v1`, and `factory.repository-context.v1`
- Data model: MissionFacts(requirements: integer, acceptance_evidence: integer,
  blocking_gaps: integer, source_hash_changed: boolean,
  evidence_class: string, source: string, requested_budget: number,
  v1_maximum: number, external_effect_requested: boolean)
- Decision facts: `requirements: integer`, `acceptance_evidence: integer`,
  `blocking_gaps: integer`, `source_hash_changed: boolean`,
  `evidence_class: measured|observed|modeled|unknown`, `source: string|empty`,
  `requested_budget: number`, `v1_maximum: number`, and
  `external_effect_requested: boolean`.
- CLI contracts: `factory product compile|slices|verify`,
  `factory mission create|verify|close|verify-completion`,
  `factory migration assess|verify`, `factory context build|verify`,
  `factory pr draft`, and `factory outcome record|summary`.
- Product artifacts live below `.factory/products`; missions live below
  `.factory/missions`; outcomes live below `.factory/outcomes`.
- Requirement IDs are content-derived and stable across order-preserving edits
  outside the requirement text.
- Product Graph and mission writes are atomic and refuse replacement unless
  `--force` is explicit or the bytes are idempotent.
- Agent providers are labels and future adapters, not runtime dependencies.
- VS Code CodeLens and the JetBrains gutter provide read-only bounded local
  evidence links for `REQ-*`, `FR-*`, and `NFR-*` without executing a command.
- The Studio endpoint remains loopback-only, token-bound, body-limited, and
  unable to publish, deploy, merge, sign, grant connectors, or inject credentials.

### Authorized bounded constants

- PRDs and Studio Product Mission requests are limited to `65536` UTF-8 bytes.
- One PRD may contain at most `500` requirement atoms.
- One value slice may contain at most `5` requirements.
- Missions default to `5` iterations, `3600` wall seconds, `100000` tokens,
  and `25` USD; callers may only reduce these values in v1.
- Mission IDs use lowercase letters, digits, and hyphens and are at most `64` characters.
- Outcome notes are limited to `4000` characters.

## SHOULD NOT - Implementation details

- Do not call a model to parse, slice, or score a PRD in v1.
- Do not infer hidden dependencies from framework conventions.
- Do not execute an agent, create a remote PR, merge, deploy, publish, or send messages.
- Do not call a starter production-ready or an outcome measured without a source.
- Do not report token or cost savings when provider usage is absent.
- Do not mutate existing application source while compiling product artifacts.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `requirements` == 0 | PRODUCT_NEEDS_INPUT |
| 2 | `acceptance_evidence` == 0 | PRODUCT_NEEDS_INPUT |
| 3 | `blocking_gaps` > 0 | BLOCK_MISSION |
| 4 | `source_hash_changed` | REPORT_MISSION_INPUT_DRIFT |
| 5 | `evidence_class` == measured and `source` == empty | REJECT_OUTCOME |
| 6 | `requested_budget` > `v1_maximum` | REJECT_BUDGET |
| 7 | `external_effect_requested` | REQUIRE_HUMAN_APPROVAL |
| 8 | else | WRITE_GOVERNED_MISSION |
