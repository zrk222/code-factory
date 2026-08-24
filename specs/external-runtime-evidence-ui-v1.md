# Spec: external-runtime-evidence-ui-v1

Status: proposed
SpecFactor-target: 0.75-2.5

## MUST — Observed-runtime Graph Ops lane

### Requirements (EARS)

- When a valid external runtime receipt is projected, the system shall emit `REQ_EXT_UI_PANEL` with marker `GRAPH_OPS_EXTERNAL_RUNTIME_UI`, an `external-evidence-panel`, and one card for each observed runtime node.
- The system shall render provider/test identity, verdict, failure kind, code version, first failed step, environment, run id, and artifact count as text facts under marker `REQ_EXT_UI_FACTS` and `GRAPH_OPS_EXTERNAL_RUNTIME_FACTS`.
- The system shall render the runner's hypothesis and recommended fix in a separate detail element with at most 512 characters under marker `REQ_EXT_UI_HYPOTHESIS` and `GRAPH_OPS_EXTERNAL_RUNTIME_HYPOTHESIS`.
- If any imported receipt is invalid or stale, the system shall emit `REQ_EXT_UI_FAIL_CLOSED` and `GRAPH_OPS_EXTERNAL_RUNTIME_FAIL_CLOSED` and instruct the user to re-import before relying on the observation.
- The system shall emit marker `GRAPH_OPS_EXTERNAL_RUNTIME_AUTHORITY_LOCKED` and `REQ_EXT_UI_AUTHORITY` and explain that imported observations cannot execute, repair, approve, merge, publish, deploy, sign, message, use credentials, or grant connectors.
- The system shall render dynamic values through text nodes and retain the existing authenticated local Graph Ops request without adding provider network calls or mutating controls under `REQ_EXT_UI_TEXT` and `GRAPH_OPS_EXTERNAL_RUNTIME_TEXT_NODE`.
- While the viewport width is 768 pixels or less, the system shall render the panel as a readable single-column layout with marker `REQ_EXT_UI_RESPONSIVE` and `GRAPH_OPS_EXTERNAL_RUNTIME_RESPONSIVE`.

## Acceptance criteria

```gherkin
Scenario: inspect an imported runtime failure
  Given Graph Ops contains one valid external_runtime node
  When the page renders the Graph Ops result
  Then the observed-runtime panel is visible
  And the first failed step, hypothesis, recommended fix, and authority boundary are readable
  And `GRAPH_OPS_EXTERNAL_RUNTIME_UI`, `GRAPH_OPS_EXTERNAL_RUNTIME_FACTS`, `GRAPH_OPS_EXTERNAL_RUNTIME_HYPOTHESIS`, `REQ_EXT_UI_PANEL`, `REQ_EXT_UI_FACTS`, and `REQ_EXT_UI_HYPOTHESIS` are present

Scenario: withhold invalid external evidence
  Given Graph Ops reports an invalid or stale external receipt
  When the page renders the Graph Ops result
  Then the panel shows GRAPH_OPS_EXTERNAL_RUNTIME_FAIL_CLOSED
  And it tells the user to re-import before relying on the observation
  And `REQ_EXT_UI_FAIL_CLOSED` is present

Scenario: preserve the authority boundary
  Given the external-runtime panel is visible
  When a user inspects it
  Then no provider request or mutation request is added
  And the panel states that execution, repair, approval, merge, publication, deployment, signing, messaging, credentials, and connectors remain locked
  And `GRAPH_OPS_EXTERNAL_RUNTIME_AUTHORITY_LOCKED` is present
  And `REQ_EXT_UI_AUTHORITY`, `REQ_EXT_UI_TEXT`, and `GRAPH_OPS_EXTERNAL_RUNTIME_TEXT_NODE` are present

Scenario: keep the lane usable on narrow screens
  Given a viewport width of 768 pixels
  When the panel renders multiple observations
  Then cards stack into a single readable column
  And `GRAPH_OPS_EXTERNAL_RUNTIME_RESPONSIVE` is present
  And `REQ_EXT_UI_RESPONSIVE` is present
```

## SHOULD — implementation boundary

- Reuse the existing `factory.graph-ops.v1` payload and session-authenticated
  loopback endpoint; do not add a second data source.
- Do not display raw provider logs or source code in the panel.
- Use the existing Graph Ops visual language and no new frontend dependency.
