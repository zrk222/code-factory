# Spec: developer-memory-brief
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Provide developers and connected coding assistants one compact, deterministic
brief that converts the current diff, existing proof evidence, and redacted
Factory Continuity metadata into source-linked next actions. The brief is
analysis-only: it does not execute tests, recall memory bodies, create records,
or grant approval.

### User roles
- Developer: needs the smallest fact-derived next proof before review.
- IDE operator: needs a readable local Studio and Graph Ops projection.
- Coding assistant: needs a local MCP response that explains evidence and
  boundaries without receiving hidden memory content.

### Requirements (EARS)
- The system shall return schema `factory.developer-memory-brief.v1`, marker `DEVELOPER_MEMORY_BRIEF_V1`, a stable `brief_sha256`, explicit false external-effect authority, and at most 50 action cards.
- When explicit workspace-relative changed paths are supplied, the system shall return marker `DEVELOPER_MEMORY_CHANGE_REVIEW_EXACT` and a next-proof action from `factory.change_review.v1` after that review normalizes the paths.
- When a declared proof input is stale, the system shall return marker `DEVELOPER_MEMORY_STALE_PROOF_ACTIONS`, the proof ID, declared gates, source review SHA-256, and action `rerun_stale_proof`.
- When a changed path has no proof-input edge, the system shall return marker `DEVELOPER_MEMORY_SCOPE_GAP_ACTION` with that path and action `bind_changed_path_to_proof` before lower-priority advice.
- Where Factory Continuity metadata exists, the system shall return marker `DEVELOPER_MEMORY_REDACTED_CONTINUITY` with only redacted counts and record identifiers; it shall not return `memory_ref`, record summaries, or recalled memory bodies.
- When local Git history is available, the system shall return marker `DEVELOPER_MEMORY_TEAM_ATTRIBUTION_LOCAL_GIT` with at most 50 observed project contributor seats, each seat's deterministic commit count, most-recent commit time, and action-path attribution; it shall label the result as local Git evidence rather than a complete identity-provider or billing-seat roster.
- If diff inspection is unavailable, the system shall return marker `DEVELOPER_MEMORY_UNAVAILABLE_EXPLICIT`, action `change_review_unavailable`, the stable failure code, and no inferred change, proof, productivity, token, or cost claim.
- While a Studio dashboard refreshes, the system shall return marker `DEVELOPER_MEMORY_STUDIO_CACHED` from at most 1 new brief calculation per 5 seconds; live assembly state may refresh separately at 1-second intervals.
- Where a local Studio or Graph Ops view renders the brief, the system shall return marker `DEVELOPER_MEMORY_VISUAL_EXPLAINED` and display every action as `what changed`, `why it matters`, `do this next`, and `evidence`; it shall visually distinguish blockers, warnings, and ready states without granting an execution authority.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: stale proof becomes an actionable next proof
  Given a green read-only proof receipt whose declared input has changed
  When a developer memory brief is requested for that input
  Then the first action is rerun_stale_proof with the proof ID and source review SHA-256
  And the request creates no workspace artifact

Scenario: brief remains bounded and analysis-only
  Given a workspace with more than 50 candidate evidence actions
  When a developer memory brief is requested twice with the same explicit changed paths
  Then each result has schema `factory.developer-memory-brief.v1` and no more than 50 action cards
  And the two `brief_sha256` values are equal
  And every external-effect authority is false

Scenario: hidden memory content remains withheld
  Given a verified Factory Continuity record with a private memory reference
  When a developer memory brief is requested
  Then only redacted continuity metadata is present
  And the memory reference and summary are absent

Scenario: observed team contribution stays evidence-scoped
  Given local Git history contains multiple contributor identities
  When a developer memory brief is requested for changed paths
  Then team seats identify the local Git evidence source and each action names only matching observed contributors
  And the brief does not claim a complete identity-provider or billing-seat roster

Scenario: unavailable diff remains honest
  Given Git diff inspection cannot determine changed paths
  When a developer memory brief is requested without explicit paths
  Then the brief contains change_review_unavailable
  And it does not claim a next proof was run

Scenario: strict requirement mutations are rejected
  Given the Developer Memory Brief contract
  When strict validator mutation runs
  Then markers include `DEVELOPER_MEMORY_BRIEF_V1`, `DEVELOPER_MEMORY_CHANGE_REVIEW_EXACT`, `DEVELOPER_MEMORY_STALE_PROOF_ACTIONS`, `DEVELOPER_MEMORY_SCOPE_GAP_ACTION`, `DEVELOPER_MEMORY_REDACTED_CONTINUITY`, `DEVELOPER_MEMORY_TEAM_ATTRIBUTION_LOCAL_GIT`, `DEVELOPER_MEMORY_UNAVAILABLE_EXPLICIT`, `DEVELOPER_MEMORY_STUDIO_CACHED`, and `DEVELOPER_MEMORY_VISUAL_EXPLAINED`
```

## SHOULD — Technical/structural
- ADR references: `docs/DIFF_TO_PROOF_REVIEW.md`, `docs/COUNTEREXAMPLE_GUARDRAIL_RESILIENCE.md`.
- Data model: immutable in-memory projection from existing review and continuity
  records; no new memory content store.
- API contract: local Studio `/api/developer-memory`; MCP
  `factory.developer_memory`; both read only.
- Team projection: local Git attribution only, bounded to 50 observed identities.
  A connected directory may later extend the roster, but no local UI may present
  Git authors as licensed seats or verified organizational membership.

## SHOULD NOT — Implementation details
- Do not make a model call, mutate continuity state, run a proof, or publish a
  metric from this feature.
- Do not infer absent team members, external identity, seat licensing, authorship,
  productivity, or review approval from local Git history.
- Do not replace Diff-to-Proof Review or Continuity authorization; compose
  their existing verified facts.

## Decision logic (factory candidates)
No HSF candidate: this is an ordered deterministic controller over existing
`change_review_available`, `unmatched_changed_paths`, `stale_proof_ids`,
`coverage_complete`, `verified_current_count`, and `expired_count` facts.
It returns unavailable first, then unmatched paths, stale proofs, coverage,
and finally redacted continuity metadata; no model or external state decides
the result.
