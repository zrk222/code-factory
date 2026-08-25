# Spec: external-runtime-evidence-triage-v1

Status: proposed
SpecFactor-target: 0.75-2.5

## MUST — Deterministic observed-runtime triage

This is a bounded extension of `external-runtime-evidence-v1`: verified external
runner observations can point a developer to the next local review step without
becoming an execution, repair, release, or provider authority.

### Requirements (EARS)

- When `GRAPH_OPS_EXTERNAL_RUNTIME_TRIAGE_READ_ONLY` is applicable to a valid external runtime receipt with verdict failed, blocked, or unknown, Graph Ops shall emit `REQ_EXT_TRIAGE_VERDICT` with action `review_external_runtime_failure`.
- If any external runtime receipt is invalid or stale, Graph Ops shall preserve `REQ_EXT_TRIAGE_PRECEDENCE` with the higher-priority `refresh_external_runtime_evidence` action and shall not emit the triage marker for that snapshot.
- The system shall emit `REQ_EXT_TRIAGE_ADVISORY` with a review prompt naming the first failed step and hypothesis before a bounded local proof or repair; it shall not claim that a provider result authorizes execution or a fix.
- The system shall keep execution, repair, approval, merge, publication, deployment, signing, messaging, credential, and connector authority false under `REQ_EXT_TRIAGE_AUTHORITY`.

### Acceptance criteria

```gherkin
Scenario: point a verified external failure to a local review
  Given one valid imported external receipt with verdict failed
  When Graph Ops compiles the workspace
  Then recommendation.action is review_external_runtime_failure
  And `GRAPH_OPS_EXTERNAL_RUNTIME_TRIAGE_READ_ONLY` is present
  And the recommendation directs review before bounded local proof or repair
  And REQ_EXT_TRIAGE_VERDICT and REQ_EXT_TRIAGE_ADVISORY are present

Scenario: stale evidence still fails closed
  Given an external receipt whose source or artifact is stale
  When Graph Ops compiles the workspace
  Then recommendation.action is refresh_external_runtime_evidence
  And the triage marker is absent
  And `REQ_EXT_TRIAGE_PRECEDENCE` is satisfied

Scenario: observed evidence cannot authorize a change
  Given a valid failed, blocked, or unknown external receipt
  When the recommendation is inspected
  Then every execution and external-effect authority remains false
  And REQ_EXT_TRIAGE_AUTHORITY is satisfied
```

## SHOULD — boundaries

- Keep this recommendation deterministic and local; no provider network calls,
  credentials, subprocesses, or writes are introduced by Graph Ops.
- Keep invalid/stale refresh precedence ahead of failure triage.
- Do not report performance, cost, or repair success without independent local
  evidence.
