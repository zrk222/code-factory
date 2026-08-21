# Spec: judgment-routing-drift-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST — Functional core
### Description
Extend the repository-tracked Engineering Judgment surface so a developer or
senior reviewer can obtain one deterministic Change Safety Case: the explicit
decisions touched, declared proof gaps, declared change novelty, decision drift
facts, recommended review attention, and the minimum unresolved human questions.
The output is a local read-only review packet, never a code-quality score,
approval, execution, or authority decision.

### User roles
- A developer who needs to see whether a local change touches a human-promoted
  engineering decision before sending it for review.
- A named domain owner who needs the smallest explicit list of unresolved proof
  or decision questions, not a generated review-comment stream.
- A staff/principal engineer who needs decision lifecycle and declared novelty
  facts without the system claiming that it inferred architecture or expertise.

### Requirements (EARS)
- The system shall return existing `factory.judgment.capsule.v1` records with unchanged canonical fields and shall return a strict `factory.judgment.capsule.v2` record only when its category, change kinds, attention floor, enforcement level, and incident references validate.
- The system shall emit `route` as one of `BLACK`, `RED`, `AMBER`, or `GREEN` and shall emit `attention` as one of `routine`, `domain`, `specialist`, or `architecture`.
- The system shall emit `has_no_matching_active_capsule` as a boolean fact.
- When a supplied `factory.judgment.change-profile.v1` has a canonical digest and exactly the requested changed paths, the system shall emit only its declared kinds as `known_change_kinds` or `novel_change_kinds` facts.
- If the change profile is absent, malformed, hash-invalid, or names a different path set, the system shall emit `profile_state=unavailable` or `profile_state=invalid` and shall not infer change kinds from source text.
- When `missing_obligation_count` is greater than zero for matching active Capsules, the system shall emit `route=RED`, `attention=specialist`, exact missing obligation IDs, and one deterministic human question per missing ID.
- When `matching_active_capsule_count` is greater than zero and `missing_obligation_count` is zero, the system shall emit `route=AMBER`, the highest declared attention floor, and named owner review.
- When `unclassified_path_count` or `novel_kind_count` is greater than zero, the system shall emit deterministic novelty facts and shall emit `attention=architecture` when `has_novel_architecture_boundary=true`; otherwise the system shall emit attention at least `specialist` for novelty.
- When `review_due_count`, `reconsideration_pending_count`, or `missing_obligation_count` is greater than zero, the system shall emit one deterministic per-Capsule drift state and shall not emit compliant, violated, safe, or approved as a drift state.
- The system shall emit decisions, questions, novelty, drift, and routing facts in sorted bounded arrays.
- The system shall return the same Safety Case facts through CLI, MCP, Graph Ops, and the JetBrains local panel while the JetBrains panel shall retain explicit local workspace confirmation before it inspects one native Change List.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: declared novelty escalates a review recommendation without source inference
  Given an active v2 Capsule that declares the change kind concurrency
  And a valid profile declares architecture-boundary for a matching changed path
  When a Change Safety Case is compiled
  Then the result lists architecture-boundary in novel_change_kinds
  And the result has attention=architecture
  And the result has source_semantics_inferred=false

Scenario: human attention is narrowed to declared unresolved facts
  Given an active matching Capsule with one missing proof obligation
  When a Change Safety Case is compiled
  Then the result has route=RED
  And the result human_questions contain the exact missing obligation ID
  And no generic finding or generated review comment is present

Scenario: decision drift is descriptive rather than an approval conclusion
  Given an active matching Capsule that is due for review
  When a Change Safety Case is compiled
  Then the result drift state is review_due
  And the result has no compliant, safe, or approved conclusion
```

## SHOULD — Technical/structural
- ADR references: `adr/0001-failure-aware-assembly.md`
- Data model: V2 Capsule and optional change profile are canonical JSON with SHA-256 digests. Existing V1 capsule digests remain unchanged. Decision facts are `store_valid` boolean, `profile_state` enum, `matching_active_capsule_count` integer, `has_no_matching_active_capsule` boolean, `missing_obligation_count` integer, `unclassified_path_count` integer, `novel_kind_count` integer, `has_novel_architecture_boundary` boolean, `review_due_count` integer, `reconsideration_pending_count` integer, `route` enum, and `attention` enum.
- API contract: `factory judgment safety-case --change-profile profile.json`; `factory.judgment_safety_case` accepts optional `change_profile`.
- Review routing: `routine|domain|specialist|architecture` is advisory and
  never proves who has authority to review, approve, merge, or release.

## SHOULD NOT — Implementation details
- Do not parse source code, git history, PR comments, Slack, tickets, IDE
  symbols, or model output to infer architectural semantics, novelty, owner,
  expertise, or review authority.
- Do not add automatic promotion, waiver, enforcement generation, test
  execution, source mutation, repair, approval, merge, publication,
  deployment, signing, messaging, or credential access.
- Do not represent a route, profile, receipt binding, or drift fact as a
  risk probability, safety finding, compliance finding, or production-readiness
  decision.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | `store_valid=false` | emit `route=BLACK` |
| 2 | `missing_obligation_count>0` | emit `route=RED`, `attention=specialist`, exact obligation questions |
| 3 | `matching_active_capsule_count>0` and `missing_obligation_count=0` | emit `route=AMBER`, named owners, max declared attention floor |
| 4 | `has_novel_architecture_boundary=true` | emit `attention=architecture` and named-decision question |
| 5 | `unclassified_path_count>0` or `novel_kind_count>0` | emit deterministic novelty and attention at least `specialist` |
| 6 | `has_no_matching_active_capsule=true` | emit `route=GREEN`, `routine_unclassified`, `attention=routine` only as an advisory route |
