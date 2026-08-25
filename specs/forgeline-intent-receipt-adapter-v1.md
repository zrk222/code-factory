# Spec: forgeline-intent-receipt-adapter-v1

Status: proposed
SpecFactor-target: 0.75-2.5

## MUST — Preserve explicit Forge intent evidence in Factoryline receipts

### Requirements (EARS)

- When `REQ_INTENT_ADAPTER_CAPTURE` is active for a Factoryline-driven Forge ship result with explicit boolean `shipped` and `intent_traceable` fields, the standard receipt shall store a `factoryline.intent-trace.v1` adapter containing the Forge intent hash, obligation result, and SHA-256 of the observed Forge ship line.
- The system shall emit `REQ_INTENT_ADAPTER_READ_ONLY` while the adapter reads Forge output and the bounded `.forge/adapter-feature/receipts.jsonl` source only; it shall not rewrite Forge receipts, call a provider, or grant execution, approval, publication, deployment, signing, messaging, credential, or connector authority.
- If `REQ_INTENT_ADAPTER_FAIL_CLOSED` applies because the CLI omits either explicit boolean, the Forge source is missing or malformed, or the values disagree, Factoryline shall omit the adapter and Graph Ops shall not infer traceability from the stage exit code.
- When `REQ_INTENT_ADAPTER_PREFER` applies because a valid or malformed Factoryline adapter exists for adapter-feature, Graph Ops shall emit that adapter as the preferred intent-trace source and shall not let a legacy `.forge` line mask an adapter integrity failure.

### Acceptance criteria

```gherkin
Scenario: capture an explicit Forge result
  Given `REQ_INTENT_ADAPTER_CAPTURE` sees a Forge ship output with shipped=true and intent_traceable=true
  And the matching Forge ship line is readable
  When Factoryline writes its standard forgeline ship receipt
  Then `factoryline.intent-trace.v1` is present with the intent hash, obligations, and a 64-character Forge receipt hash

Scenario: preserve the evidence boundary
  Given `REQ_INTENT_ADAPTER_READ_ONLY` is active
  When the adapter is produced
  Then the upstream Forge receipt remains byte-for-byte unchanged
  And every authority flag is false

Scenario: omit inferred evidence
  Given `REQ_INTENT_ADAPTER_FAIL_CLOSED` applies because intent_traceable is missing or the Forge source is malformed
  When Factoryline records the ship stage
  Then no adapter is written
  And Graph Ops reports the feature as untraceable or unverified

Scenario: prefer the explicit adapter
  Given `REQ_INTENT_ADAPTER_PREFER` finds an adapter and a legacy Forge ship line for the same feature
  When Graph Ops builds its local snapshot
  Then exactly one intent-trace node is projected from the adapter
  And a malformed adapter remains untraceable instead of falling back to the legacy line
```

## SHOULD — boundaries

- Keep the adapter local and filesystem-based; do not add a provider endpoint,
  network client, mutation control, or publication path.
- Preserve upstream Forge hashes and receipt ordering; the adapter is an
  observation bridge, not a signature or a new production-readiness claim.
