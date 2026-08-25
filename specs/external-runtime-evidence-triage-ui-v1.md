# Spec: external-runtime-evidence-triage-ui-v1

Status: proposed
SpecFactor-target: 0.75-2.5

## MUST — Review-first Graph Ops callout

### Requirements (EARS)

- When `GRAPH_OPS_EXTERNAL_RUNTIME_TRIAGE_UI` is shown for a valid failed, blocked, or unknown observation, the Graph Ops page shall display `REQ_EXT_TRIAGE_UI_COPY` with the `review_external_runtime_failure` action and a first-step/hypothesis review prompt.
- The system shall render `REQ_EXT_TRIAGE_UI_TEXT` through text nodes with no HTML insertion and shall display the observed-only boundary beside the triage callout.
- If an external receipt is invalid or stale, the page shall hide `REQ_EXT_TRIAGE_UI` and display `REQ_EXT_TRIAGE_UI_FAIL_CLOSED` with the refresh-before-reliance instruction.
- The system shall render `REQ_EXT_TRIAGE_UI_AUTHORITY` with explicit copy that no automatic repair, execution, approval, merge, publication, deployment, signing, messaging, credential use, or connector grant is available.
- While the viewport width is 768 pixels or less, the page shall render `REQ_EXT_TRIAGE_UI_RESPONSIVE` content in one readable column without horizontal overflow.

### Acceptance criteria

```gherkin
Scenario: make the next review visible
  Given `GRAPH_OPS_EXTERNAL_RUNTIME_TRIAGE_UI` is shown for a failed observation
  When the Graph Ops page renders the external evidence lane
  Then `REQ_EXT_TRIAGE_UI_COPY` shows review_external_runtime_failure
  And the first failed step and hypothesis are named as review inputs
  And the observed-only boundary remains visible

Scenario: keep stale observations fail closed
  Given an invalid or stale external receipt
  When the Graph Ops page renders the external evidence lane
  Then `REQ_EXT_TRIAGE_UI` is hidden
  And `REQ_EXT_TRIAGE_UI_FAIL_CLOSED` instructs the user to refresh before reliance

Scenario: keep repair authority locked
  Given a valid failed, blocked, or unknown observation
  When the triage callout is inspected
  Then `REQ_EXT_TRIAGE_UI_AUTHORITY` says no automatic repair or external effect is available
  And `REQ_EXT_TRIAGE_UI_TEXT` renders dynamic values as text nodes

Scenario: preserve narrow-screen readability
  Given a viewport width of 768 pixels
  When the triage callout renders
  Then `REQ_EXT_TRIAGE_UI_RESPONSIVE` stacks the action and explanation without horizontal overflow
```

## SHOULD — boundaries

- Reuse the existing Graph Ops payload and external-runtime panel; do not add a
  second endpoint or provider client.
- Keep the callout explanatory and non-interactive. Review is a human next step,
  not an execution button.
