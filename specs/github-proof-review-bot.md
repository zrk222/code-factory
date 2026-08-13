# Spec: github-proof-review-bot
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core
### Description
Provide one deterministic, evidence-bound GitHub pull-request Proof Review for
a developer or reviewer who needs the exact changed scope, declared proof gaps,
and next fact-derived action before treating an AI or human change as ready.
The adapter consumes only the existing `factory.change_review.v1` facts and
turns them into one check payload, one compact Markdown walkthrough, and
optional local artifacts. It can coexist with CodeRabbit or another AI reviewer
but does not ingest their credentials, call their APIs, or treat their comments
as verification evidence.

### User roles
- Developer: sees an exact proof gap before asking for or merging a review.
- Reviewer: receives one bounded PR walkthrough tied to the reviewed commit.
- Engineering lead: configures one repository workflow without granting a bot
  merge, approval, write-source, or external-provider authority.

### Requirements (EARS)
- The system shall return marker `GITHUB_PROOF_REVIEW_V1` and schema `factory.github_proof_review.v1` for a valid Diff-to-Proof Review payload and a 40-character lowercase Git commit SHA.
- When a valid Change Review is supplied, the system shall recompute its canonical review SHA-256 before rendering and reject a modified payload with marker `GITHUB_PROOF_REVIEW_INPUT_INVALID` without writing an artifact.
- The system shall return marker `GITHUB_PROOF_REVIEW_SHA_BOUND`, preserve the exact changed paths, findings, next action, unproven claims, and review SHA-256, and bind one `head_sha` equal to the caller-supplied commit SHA.
- The system shall return marker `GITHUB_PROOF_REVIEW_COHORTS_EXACT` with sorted, non-empty deterministic path cohorts, where every changed path appears exactly once and every cohort label is derived only from a documented path-prefix table.
- The system shall return marker `GITHUB_PROOF_REVIEW_CHECK_ADVISORY` with one completed GitHub Check request named `FactoryLine / Proof Review`, conclusion `neutral`, and no approval, merge, publication, deployment, signing, messaging, credential, connector, source-write, test-execution, or repair authority.
- The system shall return marker `GITHUB_PROOF_REVIEW_WALKTHROUGH_EXACT` with one Markdown walkthrough containing the commit SHA, review SHA-256, cohorts, fact-derived next action, findings, unproven claims, authority boundary, and existing deterministic Mermaid review map.
- When the caller supplies an output directory, the system shall return marker `GITHUB_PROOF_REVIEW_ARTIFACTS_OPTIONAL`, write only JSON and Markdown artifacts below that directory, and return SHA-256-bound paths; without an output directory, it shall not write a file.
- When the local CLI receives a root, base, optional changed paths, and head SHA, the system shall return marker `GITHUB_PROOF_REVIEW_LOCAL_ONLY`, compile a current Diff-to-Proof Review through `factory github proof-review`, then return the GitHub Proof Review payload without calling a network service.
- When a non-fork pull request triggers the opt-in workflow, the system shall return marker `GITHUB_PROOF_REVIEW_WORKFLOW_SCOPED`, use only `contents: read`, `pull-requests: write`, and `checks: write`, create or update one stable marker-comment, and create one advisory Check for the current head SHA without using `pull_request_target`, `contents: write`, automatic approval, merge, or source modification.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: render an evidence-bound pull-request walkthrough
  Given a valid Diff-to-Proof Review for one changed path and commit SHA abcdefabcdefabcdefabcdefabcdefabcdefabcd
  When GitHub Proof Review renders the payload
  Then the payload has marker `GITHUB_PROOF_REVIEW_V1` and schema `factory.github_proof_review.v1`
  And the payload preserves the review SHA and changed path
  And it contains one neutral advisory Proof Review Check request
  And the Markdown contains the commit SHA, next action, and authority boundary
  And every changed path appears in exactly one deterministic cohort

Scenario: reject a modified review before publishing a payload
  Given a Diff-to-Proof Review whose finding text was modified after its SHA was recorded
  When GitHub Proof Review validates the payload
  Then it rejects the input with GITHUB_PROOF_REVIEW_INPUT_INVALID
  And it writes no artifact

Scenario: use the local CLI without a GitHub credential
  Given a workspace with an explicit changed path and a supplied commit SHA
  When factory github proof-review runs with JSON output
  Then it returns marker `GITHUB_PROOF_REVIEW_LOCAL_ONLY`, an advisory check request, and compact walkthrough
  And it does not call a network service, create a GitHub Check, or write source files

Scenario: publish one advisory pull-request surface
  Given the opt-in workflow runs on a non-fork pull request
  When its local review succeeds
  Then it returns marker `GITHUB_PROOF_REVIEW_WORKFLOW_SCOPED` and creates or updates the one stable Proof Review comment
  And it creates one neutral check for the pull request head SHA
  And it does not approve, merge, or modify the pull request

Scenario: reject strict requirement mutations
  Given the GitHub Proof Review contract
  When strict validator mutation runs
  Then contract markers include GITHUB_PROOF_REVIEW_V1, GITHUB_PROOF_REVIEW_SHA_BOUND, GITHUB_PROOF_REVIEW_COHORTS_EXACT, GITHUB_PROOF_REVIEW_CHECK_ADVISORY, GITHUB_PROOF_REVIEW_WALKTHROUGH_EXACT, GITHUB_PROOF_REVIEW_ARTIFACTS_OPTIONAL, GITHUB_PROOF_REVIEW_LOCAL_ONLY, GITHUB_PROOF_REVIEW_WORKFLOW_SCOPED, and GITHUB_PROOF_REVIEW_INPUT_INVALID
```

## SHOULD - Technical/structural
- ADR references: Diff-to-Proof Review authority boundary and Enterprise PR Assurance.
- Data model: GitHub Proof Review payload with review hash, head SHA, exact path cohorts, one advisory check request, one Markdown walkthrough, and optional artifact digests.
- API contract: `factory github proof-review --root workspace --base main --head-sha abcdefabcdefabcdefabcdefabcdefabcdefabcd` with repeatable `--changed`, optional `--out-dir`, and `--json`.
- Serialization contract: payload and artifacts use canonical UTF-8 JSON; artifact names use `github-proof-review-` plus the first 12 hexadecimal characters of the payload SHA-256.
- Cohort table: `specs/` and `requirements/` map to `contracts`; `tests/` and `test/` map to `tests`; `.github/`, `deploy/`, and `infra/` map to `delivery`; `docs/` maps to `docs`; source paths map to `implementation`; unmatched paths map to `other`.

## SHOULD NOT - Implementation details
- Do not create a CodeRabbit client, ingest CodeRabbit output, retain opaque AI learnings, or imply that CodeRabbit is required.
- Do not write source, execute tests, post a network request from the CLI, make an automatic repair, or use a model result as a blocking fact.
- Do not auto-approve, merge, close, label, assign, or modify a pull request.

## Decision logic (factory candidates)
This feature has no HSF business-decision candidate. It is an ordered,
deterministic adapter: validate the source review SHA first; group each exact
changed path next; render the advisory check and walkthrough last. Any invalid
input stops before artifact output. The GitHub workflow is a supervised delivery
adapter for the already-rendered local payload and cannot alter its verdict.
