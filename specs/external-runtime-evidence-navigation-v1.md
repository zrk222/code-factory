# Spec: external-runtime-evidence-navigation-v1

Status: proposed
SpecFactor-target: 0.75-2.5

## MUST — Navigate from observed runtime evidence to the matching local node

### Requirements (EARS)

- When `REQ_EXT_NAV_JUMP` is rendered for a valid external runtime observation, the Graph Ops page shall emit an `Inspect node details` control that targets the observation's matching local graph node.
- The system shall render `REQ_EXT_NAV_READ_ONLY` by reusing local node selection and scrolling only; the control shall not call a provider, mutate workspace state, authorize execution, or infer a repair.
- If `REQ_EXT_NAV_MISSING` is true because the matching graph node is unavailable, the control shall emit a disabled state and report that the target is unavailable without inventing a substitute.
- While the viewport width is 768 pixels or less, the page shall render `REQ_EXT_NAV_RESPONSIVE` as a full-width, readable control with a minimum 44-pixel target.

### Acceptance criteria

```gherkin
Scenario: inspect the exact observed node
  Given `REQ_EXT_NAV_JUMP` is rendered for a valid external runtime observation
  When the reviewer selects Inspect node details
  Then the matching graph node is selected and brought into view
  And the selected node detail shows the observation facts

Scenario: keep navigation read only
  Given `REQ_EXT_NAV_READ_ONLY` is rendered
  When the reviewer selects Inspect node details
  Then only local selection, focus, and scrolling occur
  And no provider call, workspace mutation, authorization, repair, merge, publication, or deployment occurs

Scenario: fail closed when a node is missing
  Given `REQ_EXT_NAV_MISSING` is true
  When the external evidence card renders
  Then its navigation control is disabled
  And the page reports that node details are unavailable without selecting another node

Scenario: preserve narrow-screen usability
  Given a viewport width of 768 pixels
  When `REQ_EXT_NAV_RESPONSIVE` renders
  Then the navigation control is full width, readable, and at least 44 pixels tall
```

## SHOULD — boundaries

- Reuse the existing `/api/graph-ops` payload and Graph Ops node selection; do not add a second endpoint or provider client.
- Keep the navigation affordance explanatory and bounded. It is an evidence locator, not an execution button.
