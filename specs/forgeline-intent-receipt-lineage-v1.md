# Spec: forgeline-intent-receipt-lineage-v1

Status: proposed
SpecFactor-target: 0.75-2.5

## MUST — expose the exact bounded Forge source location

### Requirements (EARS)

- When `REQ_INTENT_LINEAGE_SOURCE` sees a hash-bound Factoryline intent adapter, Graph Ops shall emit the normalized relative Forge receipt source and the 1-based line number of the exact ship record used for binding.
- If `REQ_INTENT_LINEAGE_FAIL_CLOSED` applies because the Forge source is missing, unreadable, malformed, or unbound, Graph Ops shall emit no fabricated source location or line number and shall preserve the existing untraceable status.
- When `REQ_INTENT_LINEAGE_FACTS` is active, the snapshot shall emit source, line, claimed hash, observed hash, and false authority flags; lineage is navigation evidence, not a signature or authorization.
- When `REQ_INTENT_LINEAGE_UI` renders a bound adapter, the read-only intent panel shall show the Forge source and line without adding an execution, repair, approval, or publication control.

### Acceptance criteria

```gherkin
Scenario: show the exact bounded Forge line
  Given `REQ_INTENT_LINEAGE_SOURCE` sees a Factoryline adapter bound to a readable Forge ship line
  When Graph Ops builds its snapshot
  Then the card exposes the normalized Forge source and a 1-based line number
  And the source and line identify the line whose hash was verified

Scenario: do not invent lineage for an unbound adapter
  Given `REQ_INTENT_LINEAGE_FAIL_CLOSED` sees an adapter with no readable matching Forge ship line
  When Graph Ops builds its snapshot
  Then the card remains untraceable
  And Forge source and line are absent or null

Scenario: preserve authority boundaries
  Given `REQ_INTENT_LINEAGE_FACTS` is active and lineage facts are present
  When a reviewer inspects the snapshot
  Then execution, approval, publication, deployment, signing, messaging, credential, and connector authority remain false

Scenario: render source navigation without controls
  Given `REQ_INTENT_LINEAGE_UI` renders a bound adapter in Graph Ops
  When the intent panel is displayed
  Then it shows the source and line as read-only facts
  And it exposes no automatic repair or execution action
```

## SHOULD — boundaries

- Read only the bounded local Factoryline receipt and Forge receipt source; do not rewrite either source or follow links outside the workspace.
- Normalize paths relative to the workspace and keep the line number tied to the exact raw line hashed for provenance.
- Treat lineage as reviewer navigation evidence, never as a signature, production-readiness claim, approval, or release authorization.
