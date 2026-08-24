# Spec: intent-trace-graph-ops-v1

Status: proposed
SpecFactor-target: 0.75-2.5

## MUST — Show the sealed intent evidence without granting authority

### Requirements (EARS)

- When `REQ_INTENT_TRACE_UI` is active for a valid local Forge `ship` receipt, Graph Ops shall render an `intent-trace-panel` with the recorded intent hash, obligation result, shipped state, and receipt-line content hash.
- The system shall emit `REQ_INTENT_TRACE_READ_ONLY` as a bounded local intent projection from `.forge/*/receipts.jsonl` only, shall select the newest valid `phase=ship` line per feature, and shall report `authority.execution`, `authority.approval`, and `authority.publication` as false.
- If `REQ_INTENT_TRACE_MISSING_FAIL_CLOSED` applies because no valid ship receipt exists, Graph Ops shall display an unverified state and emit `REQ_INTENT_TRACE_FAIL_CLOSED`; it shall never infer or claim traceability.
- If `REQ_INTENT_TRACE_SOURCE_FAIL_CLOSED` applies because a receipt source is malformed, blocked, or lacks explicit `intent_traceable=true`, Graph Ops shall display a review-required state and emit `REQ_INTENT_TRACE_FAIL_CLOSED`; it shall never infer or claim traceability.
- While `REQ_INTENT_TRACE_RESPONSIVE` applies at a viewport width of 768 pixels or less, Graph Ops shall render the intent trace facts as one readable column without horizontal overflow.

### Acceptance criteria

```gherkin
Scenario: show a traceable local Forge receipt
  Given `REQ_INTENT_TRACE_UI` is active for a valid local Forge ship receipt that records intent_traceable=true
  When Graph Ops renders the intent trace panel
  Then the panel shows the intent hash, obligations, shipped state, and receipt-line hash
  And the panel marks the receipt traceable without granting approval or execution authority

Scenario: preserve a read-only boundary
  Given `REQ_INTENT_TRACE_READ_ONLY` is rendered in the intent trace panel
  When a reviewer inspects its facts
  Then Graph Ops reads only bounded local receipt files
  And no provider call, workspace mutation, execution, approval, publication, or deployment occurs

Scenario: fail closed when intent evidence is incomplete
  Given `REQ_INTENT_TRACE_MISSING_FAIL_CLOSED` applies because no valid traceable ship receipt is available
  When Graph Ops renders the intent trace panel
  Then it says intent traceability is unverified or requires review
  And `REQ_INTENT_TRACE_FAIL_CLOSED` is present

Scenario: reject a malformed receipt source
  Given `REQ_INTENT_TRACE_SOURCE_FAIL_CLOSED` applies to a malformed, blocked, or untraceable receipt source
  When Graph Ops renders the intent trace panel
  Then it shows a review-required state and `REQ_INTENT_TRACE_FAIL_CLOSED`
  And it does not infer intent traceability

Scenario: preserve narrow-screen readability
  Given a viewport width of 768 pixels
  When `REQ_INTENT_TRACE_RESPONSIVE` renders the intent trace facts
  Then the intent facts stack in one readable column without horizontal overflow
```

## SHOULD — boundaries

- Reuse the existing Graph Ops snapshot and local Forge receipt store; do not
  add a provider endpoint, network client, mutation control, or approval path.
- Hash the raw receipt line for provenance only; a receipt hash is not a
  signature and a traceable result is not a production-readiness claim.
