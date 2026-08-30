# Spec: continuous-proof-operations-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core
### Description
Join a human-authored intent artifact, exact changed paths, deterministic diff-to-proof analysis, optional observed-agent evidence, and optional sealed repair evidence into one local Continuous Proof Operations record. The record gives developers and teams one closed next action without granting merge, deployment, or approval authority.

### User roles
- Developer: selects the intent artifact and exact changed paths.
- Reviewer: inspects the unified proof record and retains final approval.
- External harness: may provide an observed-session receipt or a scoped repair patch, but cannot author the final verdict.

### Declared facts
- `input_bindings_valid`: every supplied path is workspace-contained and every supplied or recorded SHA-256 matches current bytes.
- `session_state`: exactly one of missing, verified_passed, verified_failed, or invalid_or_stale.
- `review_blocking`: whether Change Review contains a blocking or required finding.
- `repair_state`: exactly not_requested, candidate_scoped, or candidate_scoped_prior.
- `repair_reverified`: whether post-repair evidence binds every repaired current byte and passes independently.
- `receipt_integrity_valid`: whether the canonical receipt digest matches and all required fields are present.

### Requirements (EARS)
- The system shall return the intent artifact, exact changed paths, change-review digest, and every optional evidence input bound by workspace-relative path and SHA-256.
- When a workflow is assessed, the system shall emit one atomic JSON receipt plus Markdown and Mermaid views under an explicit workspace-contained directory.
- When a verified passing observed-session receipt is supplied and the change review has no blocking or required finding, the system shall route the record to `review_ready` while preserving human final approval.
- If observed-session evidence is absent, invalid, stale, or failed, the system shall route to `evidence_required` or `human_required` with one deterministic next action.
- If a repair patch is supplied, the system shall require a verified sealed repair scope, inspect the patch without applying it, and route to `reverification_required` until a fresh passing observed-session receipt is bound.
- When a prior `reverification_required` receipt is supplied after external human patch application, the system shall require every prior repair path in the new changed paths and require a passing `post_repair` observed session whose after-hashes equal every current repaired byte before routing to `review_ready`.
- If the intent artifact, observed-session receipt, repair scope, repair patch, or receipt bytes drift after assessment, verification shall fail closed.
- The system shall inspect at most 500 receipt files and return `verified_record_count`, `route_counts`, and `claim_limits` stating "Records are not unique users" and "No time, token, cost, quality, or productivity savings are inferred".
- The system shall project bounded Continuous Proof Operations counts and the latest route into Graph Ops read-only state.
- The system shall never execute a command, apply a patch, approve, commit, merge, publish, deploy, sign, message, access credentials, or grant a connector.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Missing execution evidence remains explicit
  Given a human-authored intent artifact and exact changed paths
  When no observed-session receipt is supplied
  Then the route is evidence_required
  And the next action requests an observed verified run

Scenario: Passing evidence becomes ready for human review
  Given a verified passing observed-session receipt
  And the change review has no blocking or required finding
  When the workflow is assessed
  Then the route is review_ready
  And final approval remains false

Scenario: Repair remains gated by fresh proof
  Given a valid sealed repair scope and in-scope patch
  When the repair candidate is bound without a fresh post-repair observed session
  Then the route is reverification_required
  And the patch is not applied

Scenario: Drift invalidates the record
  Given a written Continuous Proof Operations receipt
  When the intent artifact bytes change
  Then receipt verification fails closed with an intent drift reason

Scenario: Graph Ops is read only
  Given one valid Continuous Proof Operations receipt
  When Graph Ops compiles its local snapshot
  Then it reports the receipt count and latest route
  And it performs no execution or approval action
```

## SHOULD - Technical/structural
- ADR references: existing Change Review, Session Recorder, Repair Sandbox, and Graph Ops contracts.
- Data model: `factory.continuous-proof.v1` receipts below `.factory/continuous-proof/example-change/`.
- API contract: Python functions plus `factory proof-ops assess|verify|history`.

## SHOULD NOT - Implementation details
- Do not add a provider-specific connector or hosted dependency.
- Do not infer user intent from changed code.
- Do not turn a passing validator into merge or release approval.
- Do not convert counts into unique-user or savings claims.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | `input_bindings_valid` is false | reject the assessment input |
| 2 | `receipt_integrity_valid` is false | return `CONTINUOUS_PROOF_INVALID` |
| 3 | `repair_state` is `candidate_scoped` and `repair_reverified` is false | route `reverification_required` |
| 4 | `session_state` is `missing` | route `evidence_required` |
| 5 | `session_state` is `verified_failed` or `invalid_or_stale` | route `human_required` |
| 6 | `review_blocking` is true | route `human_required` |
| 7 | `session_state` is `verified_passed`, `review_blocking` is false, and `repair_state` is `not_requested` | route `review_ready` with human final approval retained |
| 8 | `session_state` is `verified_passed`, `repair_state` is `candidate_scoped_prior`, and `repair_reverified` is true | route `review_ready` with human final approval retained |
