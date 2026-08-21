# Spec: judgment-graph-safety-case
Status: approved
SpecFactor-target: 0.75-2.5

## MUST — Functional core
### Description
Give a developer, reviewer, or team a small, repository-tracked record of the
engineering decisions that must survive an agent-assisted change. A Judgment
Capsule is proposed by one named human and promoted by a different named human;
it binds an explicit path scope, rationale references, evidence references,
proof obligations, an owner, a review date, and any superseded decision.

`factory judgment safety-case` maps only explicit changed paths to active,
valid Capsules and supplied, hash-bound proof receipts. It returns a
deterministic review route. It does not infer policy from model output, Slack,
or chat; execute a test; modify source; approve a change; repair; merge;
publish; deploy; sign; or access credentials.

### User roles
- A developer who needs one repeatable explanation of a decision an AI or
  reviewer must not rediscover on every change.
- A senior reviewer who needs missing proof obligations and unclassified paths
  called out before review, without a synthetic risk score.
- A team lead who needs Graph Ops to show active, expiring decision contracts
  without granting Graph Ops execution authority.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- The system shall accept only `factory.judgment.capsule.v1` Capsule records
  with exact schema fields, normalized workspace-relative scopes, bounded text,
  non-empty proof obligations, an owner, and an ISO-8601 review date.
- When a named human proposes a Capsule, the system shall store the Capsule
  with `state=proposed` and shall exclude that Capsule from Change Safety Case
  matching.
- If the promotion actor differs from the proposer, the system shall store `state=active` and the named promoter for a valid proposed Capsule.
- If the promotion actor equals the proposer, the system shall reject promotion without changing the Capsule store.
- If a named human records reconsideration for an active Capsule, the system shall store the successor proposal ID and retain the active Capsule until independent promotion.
- If a Change Safety Case receives explicit changed paths, the system shall emit matching active Capsule IDs and every unmatched path as `unclassified_changed_path`.
- If a matching active Capsule has an invalid or absent obligation receipt, the system shall emit `route=RED` and the exact missing obligation IDs.
- If matching active Capsules have all valid hash-bound obligation receipts, the system shall emit `route=AMBER` and named owner review.
- When no active Capsule matches an explicit changed path, the system shall
  route `GREEN` only as `routine_unclassified`; the result shall retain the
  unclassified paths and shall not claim that the change is safe or approved.
- If a Capsule store or Capsule is malformed, the system shall fail closed with
  `JUDGMENT_CAPSULE_INVALID` and shall not use an older record as a fallback.
- The system shall emit active Capsule facts into Graph Ops and the local Graph
  Ops UI without changing Capsule state or granting execution authority.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: promotion requires independent human authority
  Given a valid Capsule proposed by Ada
  When Ada attempts to promote the Capsule
  Then promotion is rejected without changing the store
  When Lin promotes the Capsule
  Then the Capsule becomes active with Lin recorded as promoter

Scenario: a missing proof obligation blocks a scoped change
  Given an active Capsule scoped to app/billing.py with a required negative test obligation
  When a Change Safety Case is requested for app/billing.py with no matching receipt
  Then the route is RED
  And the missing obligation is listed
  And no test or repair is executed

Scenario: an unmatched path remains visible
  Given an active Capsule scoped to app/billing.py
  When a Change Safety Case is requested for docs/notes.md
  Then docs/notes.md is listed as an unclassified changed path
  And the result does not claim an engineering decision for that path
```

## SHOULD — Technical/structural
- ADR references: `adr/0001-failure-aware-assembly.md`
- Data model: tracked `judgment/capsules.json` uses schema
  `factory.judgment.store.v1`. A Capsule uses schema
  `factory.judgment.capsule.v1`, state `proposed|active|superseded`, unique
  ID, proposer/promoter, scoped paths, evidence references, named proof
  obligations, owner, review date, optional successor, and a canonical digest.
  Decision input fact `store_valid` is boolean.
  Decision input fact `active_capsule_valid` is boolean.
  Decision input fact `matching_active_capsule_count` is integer.
  Decision input fact `has_matching_active_capsule` is boolean.
  Decision input fact `missing_obligation_count` is integer.
  Decision input fact `unclassified_changed_paths` is array.
  Decision output facts are `route` and `review_reasons`.
- API contract: `factory judgment propose|promote|reconsider|status|safety-case`.
  `safety-case` is analysis-only and accepts repeatable `--changed` plus
  optional repeatable `--proof-receipt` paths.
- Decision logic: `BLACK` for an invalid store or active Capsule; `RED` for a
  matching Capsule with missing obligation evidence; `AMBER` for matching
  Capsules whose declared receipt bindings are present; `GREEN` for no matching
  Capsule, while preserving unclassified paths. These labels are review routes,
  never production readiness, risk probability, merge authority, or deployment
  authority.

## SHOULD NOT — Implementation details
- Do not invoke a model or import chat, Slack, Notion, or memory contents to
  create, promote, or alter a Capsule.
- Do not infer that a proof receipt executed successfully: show only its
  declared hash-bound fields and any validated supplied binding.
- Do not mutate source, tests, VCS, Change Lists, CI, releases, Marketplace,
  credentials, external services, or Graph Ops authorization state.
- Do not replace a human-promoted decision with a model suggestion or a
  same-person promotion.

## Decision logic (factory candidates)
<!-- Ordered business rules over extracted facts. specline handoff compiles
     these via HSF instead of letting agents improvise them. -->
| # | if | then |
|---|----|------|
| 1 | `store_valid=false` or `active_capsule_valid=false` | emit `route=BLACK` and fail closed |
| 2 | `matching_active_capsule_count>0` and `missing_obligation_count>0` | emit `route=RED` and exact missing obligation IDs |
| 3 | `matching_active_capsule_count>0` and `missing_obligation_count=0` | emit `route=AMBER` and named owner review |
| 4 | `has_matching_active_capsule=false` | emit `route=GREEN`, `routine_unclassified`, and `unclassified_changed_paths` |
