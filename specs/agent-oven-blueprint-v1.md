# Agent Oven Versioned Blueprint v1

## Outcome

Compile novice recipes and enterprise-custom workflows into one typed, versioned, auditable Agent Blueprint.

## Blueprint ingredients

1. Trigger: manual, schedule, webhook, or business event.
2. Knowledge: selected Knowledge Wall scopes and connector references.
3. Work line: ordered steps with explicit kind and bounded instruction.
4. Actions: connector-bound operations; no implicit tool discovery.
5. Human gates: step-level gates plus global authority mode.
6. Memory: none, run-only, or governed history.
7. Model route and hard budget.
8. Evidence: essential or full proof chain.

## Lifecycle

- Applying a recipe creates only an editable draft.
- Saving appends an immutable version and computes server-side platform-credit estimate.
- Simulation returns stages, authorization needs, connector blockers, and budget before activation.
- Activation requires admin authorization and zero blocking readiness findings.
- Active versions are never edited in place; the next save creates a new head.

## Enterprise inheritance

Organization policies may later lock ingredients. The v1 data contract keeps every ingredient explicit so policy evaluation can reject overrides without parsing prose.
