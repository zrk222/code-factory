# Spec: release-decision-visibility-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core

### Description

Make the local release-workflow diagnosis discoverable in the read-only product
and agent guidance. The view helps a maintainer or connected agent distinguish a
broken local workflow from a feature-specific decision that still needs a named
feature. It must never turn that local diagnosis into a claim about Marketplace,
provider, publication, or approval state.

### User roles

- Maintainer: sees the smallest local repair before checking a provider.
- Connected coding agent: sees the same bounded local facts and command
  template, without gaining release or provider authority.
- Reviewer: can tell whether a static workflow boundary is blocked, healthy,
  absent, or waiting for a named feature decision.

### Requirements (EARS)

- When `RELEASE_WORKFLOW_APPLIES` receives `applicable=true` and `ok=false`, the system shall project `LOCAL_WORKFLOW_BLOCKED` with the declared failed check identifiers. [R1]
- When `RELEASE_WORKFLOW_HEALTHY` receives `applicable=true` and `ok=true`, the system shall project `FEATURE_DECISION_REQUIRED` and one bounded local named-feature decision route. [R2]
- When `RELEASE_WORKFLOW_ABSENT` receives `applicable=false`, the system shall project `RELEASE_WORKFLOW_NOT_APPLICABLE` without inventing a release workflow or provider state. [R3]
- When `RELEASE_DECISION_VIEW_READ` reads the release guidance, the system shall return `RELEASE_DECISION_GRAPH_READ_ONLY` and `provider_state=unobserved`. [R4]
- When `RELEASE_DECISION_GUIDANCE_READ` reads the agent guidance, the system shall return the same named-feature local route before a user interprets a local release failure as a provider failure. [R5]
- If `RELEASE_DECISION_AUTHORITY_READ` reads either surface, the system shall return `RELEASE_DECISION_ZERO_AUTHORITY` for execution, approval, repair, merge, publication, deployment, signing, messaging, credential, and connector authority. [R6]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: a broken declared workflow is visible before feature evidence
  Given RELEASE_WORKFLOW_APPLIES returns applicable=true and ok=false
  When the read-only inspection surface is read
  Then the release decision state is LOCAL_WORKFLOW_BLOCKED

Scenario: a healthy workflow requires a named feature decision
  Given RELEASE_WORKFLOW_HEALTHY returns applicable=true and ok=true
  When the read-only inspection surface is read
  Then the release decision state is FEATURE_DECISION_REQUIRED

Scenario: absent workflow is not inferred
  Given RELEASE_WORKFLOW_ABSENT returns applicable=false
  When the read-only inspection surface is read
  Then the release decision state is RELEASE_WORKFLOW_NOT_APPLICABLE

Scenario: a local release card never becomes provider evidence
  Given RELEASE_DECISION_VIEW_READ reads the release guidance
  When a connected agent selects the local diagnosis
  Then provider_state is unobserved

Scenario: IDE agents receive the same safe release route
  Given RELEASE_DECISION_GUIDANCE_READ reads the agent guidance
  When release preparation is triggered
  Then the release_decision capability pack names factory.release_decision

Scenario: visibility does not grant authority
  Given RELEASE_DECISION_AUTHORITY_READ reads either surface
  When a user selects the release decision guidance
  Then every authority flag is false
```

## SHOULD — Technical/structural

- ADR references: release-decision-card, release-integrity, Mission Control,
  Graph Ops, IDE playbook, and MCP authority boundaries.
- Data model: one `release_decision` Graph Ops node with `state`,
  `workflow_marker`, `workflow_ok`, `failed_check_ids`, `provider_state`,
  `provider_contacted`, `feature_required`, `next_action`, and explicit
  zero-authority facts.
- API contract: `factory graph ops --root . --json` adds the node and
  `factory.ide_playbook` adds a read-only `release_decision` capability pack;
  a feature-specific card remains `factory release decision payment-service
  --root . --json` or MCP `factory.release_decision`.
- Deterministic ordering: the node state derives only from Mission Control's
  existing `release_workflow_integrity` projection; failed identifiers preserve
  the projection order.

## SHOULD NOT — Implementation details

- Do not contact a provider, credential store, repository host, marketplace,
  signing service, or network endpoint.
- Do not execute a release check, repair, Git operation, publish operation, or
  feature verification from Graph Ops or the playbook.
- Do not infer provider rejection, publication, processing, availability, or
  approval from a local workflow result.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `applicable=true` and `ok=false` | `LOCAL_WORKFLOW_BLOCKED`; retain failed checks; next `repair_release_workflow` |
| 2 | `applicable=true` and `ok=true` | `FEATURE_DECISION_REQUIRED`; next exact named-feature local decision command |
| 3 | `applicable=false` | `RELEASE_WORKFLOW_NOT_APPLICABLE` |
