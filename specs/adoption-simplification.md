# Spec: adoption-simplification
Status: approved
SpecFactor-target: 0.75-2.5

## MUST — Functional core
### Description
Provide one plain-language entry point for individual developers, engineering
teams, and enterprise evaluators. The entry point explains the user's problem,
the smallest appropriate Code Factory workflow, the evidence produced, and the
authority that remains human-controlled. Advanced module names remain available
only as secondary labels.

### User roles
- Individual developer or vibe coder checking whether a test can fail.
- Engineering team reviewing what a coding agent changed and whether it matched intent.
- Enterprise evaluator assessing governed agent evidence without granting execution authority.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- When the guide command runs without a journey, the system shall render `ADOPTION_GUIDE_RENDERED` with exactly three journeys named `solo`, `team`, and `enterprise`; every journey shall contain a problem, first command, expected local evidence, next safe action, and authority boundary; only `factory first-proof --root .` shall be marked primary; `solo` shall be recommended; the action count shall be zero; and AppForge shall appear only in `triggered_capabilities` for explicit mobile delivery work. [R10]
- When the guide command runs with the team journey, the system shall render `TEAM_GUIDE_RENDERED` with exactly the `team` journey and an action count of zero. [R20]
- When Graph Ops loads, the system shall render `GRAPH_OPS_START_HERE` before `GRAPH_OPS_SPECIALIZED_MODULES` and keep every guide action read-only. [R30]
- If an unsupported journey is supplied, the system shall return `E_GUIDE_JOURNEY`, list `solo`, `team`, and `enterprise`, and execute zero actions. [R40]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: A new individual developer asks where to start
  Given no journey is selected
  When the user runs factory guide
  Then ADOPTION_GUIDE_RENDERED recommends solo, marks factory first-proof --root . as the only primary command, reports an action count of zero, and lists mobile delivery only under triggered_capabilities

Scenario: A team asks how to review agent work
  Given the team journey is selected
  When the guide is rendered
  Then TEAM_GUIDE_RENDERED returns exactly the team journey with an action count of zero

Scenario: Graph Ops progressively discloses complexity
  Given Graph Ops loads
  When the first guidance panel is rendered
  Then GRAPH_OPS_START_HERE appears before GRAPH_OPS_SPECIALIZED_MODULES and every guide action is read-only

Scenario: An invalid journey is requested
  Given a journey outside solo, team, and enterprise
  When the guide is rendered
  Then E_GUIDE_JOURNEY lists solo, team, and enterprise and zero actions execute
```

## SHOULD — Technical/structural
- ADR references: none; this is a read-only projection over existing capabilities.
- Data model: `factory.adoption-guide.v1` with three immutable journey records.
- API contract: Python `adoption_guide(journey: str | None) -> dict[str, Any]`; CLI `factory guide [--journey solo|team|enterprise] [--json]`.

## SHOULD NOT — Implementation details
<!-- Leave the "how" to the plan/tasks unless it is a systemic invariant -->

## Decision logic (factory candidates)
<!-- Ordered business rules over extracted facts. specline handoff compiles
     these via HSF instead of letting agents improvise them. -->
No prompt-routed factory candidate is permitted. Selection is implemented by
the deterministic journey allowlist and read-only projection rules above.
