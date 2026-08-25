# Spec: forgeline-intent-lineage-navigation-v1

Status: proposed
SpecFactor-target: 0.75-2.5

## MUST — make verified lineage easy to inspect

### Requirements (EARS)

- When `REQ_INTENT_LINEAGE_NAV_READ_ONLY` sees a bound `intent_source` node, the intent card shall render a visible `Intent trace → Forge ship line` path with the normalized source and exact line.
- When `REQ_INTENT_LINEAGE_NAV_BUTTON` sees a bound source node, Graph Ops shall render one accessible `Inspect source` navigation action that selects the existing graph node and performs no write, provider call, execution, repair, approval, publication, deployment, signing, messaging, credential, or connector action.
- If `REQ_INTENT_LINEAGE_NAV_FAIL_CLOSED` sees no matching bound source node, the card shall render `No traversable Forge lineage` and shall not offer source navigation.
- When `REQ_INTENT_LINEAGE_NAV_RESPONSIVE` renders the lineage path, its layout shall remain readable at the existing mobile breakpoint and use text nodes rather than unsafe HTML injection.

### Acceptance criteria

```gherkin
Scenario: show the verified lineage path
  Given `REQ_INTENT_LINEAGE_NAV_READ_ONLY` sees an intent trace with a matching source node
  When Graph Ops renders the intent card
  Then the card shows Intent trace, Forge ship line, normalized source, and exact line

Scenario: navigate without authority
  Given `REQ_INTENT_LINEAGE_NAV_BUTTON` sees a matching bound source node
  When a reviewer chooses Inspect source
  Then the existing Graph Ops source node is selected and focused
  And no workspace, provider, execution, repair, approval, publication, deployment, signing, messaging, credential, or connector state changes

Scenario: withhold navigation when lineage is not verified
  Given `REQ_INTENT_LINEAGE_NAV_FAIL_CLOSED` sees no matching bound source node
  When Graph Ops renders the intent card
  Then it shows No traversable Forge lineage
  And it renders no Inspect source action

Scenario: keep the polish safe on narrow screens
  Given `REQ_INTENT_LINEAGE_NAV_RESPONSIVE` renders the lineage path
  When the page is displayed at the existing mobile breakpoint
  Then the path wraps without unsafe HTML injection or hidden source facts
```

## SHOULD — boundaries

- Reuse the existing Graph Ops selection/focus path; do not create a second navigation mechanism.
- Keep the action local and read-only; it must never infer, refresh, repair, execute, or authorize evidence.
