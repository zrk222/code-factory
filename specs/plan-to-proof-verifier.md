# Spec: plan-to-proof-verifier
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core
### Description
Provide a deterministic, provider-neutral **Plan-to-Proof Review** for teams
receiving a pull request from an autonomous coding system. It binds one
explicit, human-approved agent plan to the exact changed paths and the existing
Diff-to-Proof Review. It makes unplanned changes, missing declared test paths,
and deep-risk paths requiring a named reviewer visible before a human decides
whether to merge or ask the worker to refine.

This is an interop envelope, not a parser for a vendor-private plan. A user may
label a valid envelope `blitzy`, `coderabbit`, or another provider, but that
label is supplied data and does not create a vendor integration claim.

### User roles
- Engineering lead: records the approved scope in a compact, reviewable plan
  envelope before an agent changes code.
- Developer: sees the smallest fact-derived refinement or review action for an
  agent-created change.
- Reviewer: receives one commit-bound GitHub Check/comment beside AI review
  feedback without granting FactoryLine source-write, approval, or merge
  authority.

### Requirements (EARS)
- The system shall return marker `PLAN_TO_PROOF_ENVELOPE_STRICT` only after accepting `factory.agent_plan.v1` JSON with an
  `approved` plan state, a non-empty named approver, unique item IDs, exact
  workspace-relative paths, explicit review tiers, and a named owner for every
  `deep` item.
- The system shall emit marker `PLAN_TO_PROOF_REVIEW_V1`; when `plan_validation=valid` and `changed_path_count` is at least one, it shall emit schema `factory.plan_proof_review.v1` with canonical plan and review SHA-256 fields plus one deterministic next-action value.
- When a changed path appears in no plan item, the system shall return marker `PLAN_TO_PROOF_UNPLANNED_PATH_PRIORITY` and
  `unplanned_changed_path` as the highest-priority finding and shall not
  describe the agent plan as complete.
- The system shall emit marker `PLAN_TO_PROOF_DECLARED_TEST_EXACT` when a changed item has non-empty `test_paths` and no declared test path is in `changed_paths`, and it shall emit `declared_test_path_missing`. A test path's presence shall not be reported as evidence that the test was executed or non-hollow.
- The system shall return marker `PLAN_TO_PROOF_DEEP_REVIEW_ROUTED` when a changed path belongs to a `deep` item and a
  `named_human_review_required` finding. A named plan owner is routing data,
  not proof that the owner reviewed or approved the change.
- The system shall return `PLAN_TO_PROOF_PLAN_INVALID` and apply the `PLAN_TO_PROOF_INVALID_REJECTED` rule when `plan_validation=invalid` because the plan contains unsupported fields, duplicate item IDs or paths, traversal or absolute paths, or a non-approved state; it shall write zero artifacts.
- When the caller supplies an output directory, the system shall return marker `PLAN_TO_PROOF_ARTIFACTS_OPTIONAL`, write only
  canonical JSON, Markdown, and Mermaid artifacts below that explicit
  directory; without it, it shall write no workspace files.
- The system shall render marker `GITHUB_PLAN_PROOF_REVIEW_CHECK_ADVISORY`; when `plan_validation=valid` and `head_sha` is exactly 40 lowercase hexadecimal characters, it shall render one neutral `FactoryLine / Proof Review` Check and one stable marker comment without a network call.
- The system shall compile marker `GITHUB_PLAN_PROOF_REVIEW_WORKFLOW_SCOPED`; when `agent_plan_present=true` in the opt-in GitHub workflow, it shall compile the plan-aware payload; when `agent_plan_present=false`, it shall compile the existing GitHub Proof Review payload. In either branch the workflow shall use `pull_request`, never `pull_request_target`, and shall not approve, merge, edit source, execute a repair, publish, deploy, or access a provider token.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: find unplanned code in an approved agent plan
  Given an approved factory.agent_plan.v1 envelope for src/service.py
  And a changed path src/secret.py
  When Plan-to-Proof Review runs
  Then the result has schema factory.plan_proof_review.v1
  And its first finding is unplanned_changed_path for src/secret.py
  And its next action is reconcile_unplanned_change

Scenario: keep deep changes routed to a human
  Given an approved plan item for src/auth.py with review tier deep and owner security-owner
  And src/auth.py changed
  When Plan-to-Proof Review runs
  Then it returns named_human_review_required
  And it does not claim security-owner reviewed the change

Scenario: preserve the no-plan GitHub workflow path
  Given an opted-in same-repository pull request without .factory/agent-plan.json
  When the GitHub workflow runs
  Then it compiles factory github proof-review
  And it publishes only the existing neutral Check and stable walkthrough

Scenario: reject a malformed envelope before output
  Given an agent plan with a duplicated item ID or a parent-traversal path
  When Plan-to-Proof Review runs
  Then it returns PLAN_TO_PROOF_PLAN_INVALID
  And it writes no artifact

Scenario: reject strict requirement mutations
  Given the Plan-to-Proof Review contract
  When strict validator mutation runs
  Then contract markers include `PLAN_TO_PROOF_ENVELOPE_STRICT`, `PLAN_TO_PROOF_REVIEW_V1`, `PLAN_TO_PROOF_UNPLANNED_PATH_PRIORITY`, `PLAN_TO_PROOF_DECLARED_TEST_EXACT`, `PLAN_TO_PROOF_DEEP_REVIEW_ROUTED`, `PLAN_TO_PROOF_INVALID_REJECTED`, `PLAN_TO_PROOF_ARTIFACTS_OPTIONAL`, `GITHUB_PLAN_PROOF_REVIEW_CHECK_ADVISORY`, and `GITHUB_PLAN_PROOF_REVIEW_WORKFLOW_SCOPED`
```

## SHOULD - Technical/structural
- ADR references: Diff-to-Proof Review authority boundary and GitHub Proof
  Review supervised delivery adapter.
- Data model: `factory.agent_plan.v1`, `factory.plan_proof_review.v1`, and
  `factory.github_plan_proof_review.v1` use canonical UTF-8 JSON and
  SHA-256-bound inputs.
- API contract: `factory plan verify --root workspace --plan plan.json` with
  repeatable `--changed`, optional `--out-dir`, and `--json`; `factory github
  plan-proof-review` adds `--head-sha` for a local, advisory Check payload.
- Workflow convention: `.factory/agent-plan.json` is optional and excluded from
  its own changed-path comparison when the example workflow compiles a
  plan-aware review.

## SHOULD NOT - Implementation details
- Do not add a Blitzy or CodeRabbit client, use their credentials, parse private
  plan formats, retain their opaque reasoning, or claim a certified vendor
  partnership.
- Do not interpret AI comments as proof, execute tests, write source, repair a
  pull request, auto-approve, merge, close, label, assign, publish, deploy, or
  bypass existing branch protections.

## Decision logic (factory candidates)
No HSF candidate: this feature deterministically validates a structured
envelope, compares exact path sets, and composes existing review facts. It
contains no business decision that must be delegated to a model or rule engine.
