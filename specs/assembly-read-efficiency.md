# Spec: Assembly read efficiency
Status: draft
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Requirements
- When `REQ_SHARE` builds 1 Graph Ops snapshot, it shall read each of the 4 shared Oracle, operations, lifecycle and repair projections exactly 1 time and use those observations for Mission Control and graph rendering. [R10]
- When `REQ_FRESH` starts a second snapshot, it shall return freshly read values from all 4 projections with zero global or persistent caches. [R20]
- When `REQ_AUTH` renders shared evidence, it shall preserve all existing blocker decisions and grant zero execution, approval or publication authority. [R30]
- When `REQ_PROFILE` profiles Mission Control, it shall emit 5 named elapsed-time spans, 5 canonical output SHA-256 fingerprints, 1 aggregate evidence digest and zero raw evidence bodies; timing shall not participate in evidence identity. [R40]

## Acceptance criteria (Gherkin)
```gherkin
Scenario: Shared facts avoid duplicate reads
  Given REQ_SHARE observes 4 shared projections
  When Graph Ops builds 1 snapshot
  Then REQ_SHARE returns each projection read exactly 1 time
  And REQ_AUTH preserves blocker decisions and zero authority
Scenario: Fresh request observes changed evidence
  Given REQ_FRESH completed 1 snapshot
  When a second snapshot observes a changed blocker
  Then REQ_FRESH returns all 4 projections read again and the blocker remains visible
  And REQ_AUTH returns zero execution, approval or publication authority
Scenario: Profiling keeps timing separate from identity
  Given REQ_PROFILE observes 5 unchanged projection outputs
  When 2 profiling requests have different elapsed times
  Then REQ_PROFILE returns equal evidence fingerprints and no raw evidence bodies
```

## SHOULD - Technical/structural
- Fingerprints serialize JSON with sorted keys, compact separators, ASCII escaping, non-finite numbers rejected, and UTF-8 encoding; this is an encoding contract, not an audit threshold.
- Share request-local observations, not trusted execution results.
- Keep the existing read-only CLI and MCP behavior compatible.

## SHOULD NOT - Implementation details
- Do not skip gates, cache approvals, claim atomic filesystem snapshots or invent speedup percentages.
