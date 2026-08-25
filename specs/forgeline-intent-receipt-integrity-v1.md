# Spec: forgeline-intent-receipt-integrity-v1

Status: proposed
SpecFactor-target: 0.75-2.5

## MUST — Bind adapter evidence to the exact Forge source

### Requirements (EARS)

- When `REQ_INTENT_BINDING_VERIFY` sees a Factoryline intent adapter and a readable bounded Forge ship line for the same feature, Graph Ops shall emit `provenance_status=bound` only when the claimed Forge-line SHA-256 and explicit shipped/intent/obligation values match the observed line.
- If `REQ_INTENT_BINDING_FAIL_CLOSED` applies because the Forge line is missing, malformed, or disagrees with the adapter, Graph Ops shall emit an untraceable card, increment the binding failure fact, and expose `GRAPH_OPS_INTENT_ADAPTER_MISMATCH` or `GRAPH_OPS_INTENT_ADAPTER_UNBOUND` without using a legacy fallback.
- The system shall emit `REQ_INTENT_BINDING_FACTS` with the claimed hash, observed hash, provenance status, and `provenance_match` boolean while every authority flag remains false.
- When `REQ_INTENT_BINDING_UI` renders a mismatch or unbound adapter, Graph Ops shall show the provenance status, both available hashes, and a review-required rationale without adding an execution or repair action.

### Acceptance criteria

```gherkin
Scenario: bind an unchanged adapter
  Given `REQ_INTENT_BINDING_VERIFY` sees an adapter whose Forge-line hash and explicit values match the current bounded ship line
  When Graph Ops builds its snapshot
  Then the card is traceable with provenance_status=bound and provenance_match=true

Scenario: reject a stale adapter
  Given `REQ_INTENT_BINDING_FAIL_CLOSED` sees a claimed Forge-line hash that differs from the current bounded ship line
  When Graph Ops builds its snapshot
  Then the card is untraceable and GRAPH_OPS_INTENT_ADAPTER_MISMATCH is present
  And no legacy line is substituted

Scenario: expose provenance facts without authority
  Given `REQ_INTENT_BINDING_FACTS` is active
  When a reviewer inspects the card
  Then the claimed and observed hashes and provenance status are visible
  And execution, approval, and publication authority remain false

Scenario: explain the blocked state in the UI
  Given `REQ_INTENT_BINDING_UI` sees an unbound or mismatched adapter
  When Graph Ops renders the intent panel
  Then it names the binding problem and shows the review-required rationale
  And it exposes no automatic repair or execution control
```

## SHOULD — boundaries

- Read only the local Factoryline receipt and bounded Forge receipt source; do
  not rewrite either source or add a network/provider integration.
- Treat a binding match as provenance evidence, never as a signature,
  production-readiness claim, approval, or release authorization.
