# Spec: diff-to-proof-review
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Provide one local, deterministic Diff-to-Proof review for a developer who has
changed a branch and needs the smallest defensible review and verification
plan. The review joins explicit changed paths, Graph Ops impact facts, existing
coverage evidence, and the established risk-diff plan into one packet and
Mermaid map. Default operation performs analysis only: it does not execute a
gate, write a source file, alter a plan, merge, publish, deploy, sign, send a
message, access a credential, or call a network service.

### User roles
- Developer: sees the exact impact and missing proof before requesting review.
- Reviewer: receives one bounded packet with facts, gaps, and unproven claims.
- Engineering lead: verifies that a proposed rerun set came from declared
  artifacts and existing policy rather than filename guesses or model output.

### Requirements (EARS)
- The system shall return schema `factory.change_review.v1` and marker `DIFF_TO_PROOF_REVIEW_V1` with a sorted, de-duplicated set of 1 through 100 workspace-relative changed paths.
- When explicit changed paths are supplied, the system shall return marker `DIFF_TO_PROOF_INPUTS_EXACT` with `input_source` equal to `explicit` and `changed_paths` equal to those normalized paths; with no paths, the system shall return Git `BASE...HEAD` paths or reject an unavailable base or empty change set without an artifact.
- The system shall return marker `DIFF_TO_PROOF_GRAPH_IMPACT_EXACT` and preserve Graph Ops matched proofs, stale rerun proofs, verified-current proofs, unmatched paths, source errors, and graph hash for the exact changed-path set.
- The system shall return marker `DIFF_TO_PROOF_COVERAGE_GAPS_EXPLICIT`, preserve the existing `requirement_coverage` payload, and add one `coverage_incomplete` finding whenever that payload has `ok: false`.
- The system shall return marker `DIFF_TO_PROOF_RERUN_PLAN_EXACT` with an ordered plan-only rerun stage list from the existing risk-diff policy and label every recommendation unexecuted.
- When `unmatched_changed_paths` has at least one path, the system shall return marker `DIFF_TO_PROOF_UNMATCHED_PRIORITY`, an `unmatched_changed_path` finding for the first unmatched path, and that finding as `next_action`.
- The system shall return marker `DIFF_TO_PROOF_MERMAID_EXPORTED` with deterministic `review_markdown` and `mermaid` strings that list unproven claims and prohibit merge, publication, deployment, signing, messaging, credential access, connector grants, and command execution.
- When the caller supplies an output directory, the system shall return marker `DIFF_TO_PROOF_ARTIFACTS_OPTIONAL`, write only JSON, Markdown, and Mermaid review artifacts below that directory, and return their SHA-256-bound paths; without an output directory, it shall not write a file.
- The system shall return marker `DIFF_TO_PROOF_NO_EXECUTION` with every external-effect authority set to `false` and shall not execute a gate, replay plan, or test command.
- The system shall return marker `DIFF_TO_PROOF_PATH_REJECTED` and reject a request before analysis when any changed path is empty, absolute, or contains parent traversal, or when more than 50 paths are supplied.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: review an explicit changed proof input without execution
  Given a workspace with one stale proof bound to input.txt
  When Diff-to-Proof Review receives changed path input.txt
  Then the packet records that proof in rerun_proofs
  And the result contains an ordered plan-only rerun stage list
  And no file is written when no output directory is supplied
  And every external-effect authority remains false
  And the contract schema is `factory.change_review.v1`

Scenario: surface an unbound code change honestly
  Given a workspace with changed path app/service.py and no declared input edge
  When Diff-to-Proof Review runs
  Then `unmatched_changed_paths` contains app/service.py
  And the first finding is unmatched_changed_path
  And the next action asks for an explicit proof binding

Scenario: write a reviewer packet only by explicit choice
  Given a review result for one changed path
  When the caller supplies a local output directory
  Then JSON, Markdown, and Mermaid artifacts are written below that directory
  And their content hashes are present in the result
  And the source workspace files remain unchanged

Scenario: reject unsafe changed-path input
  Given a caller supplies ../secret.txt
  When Diff-to-Proof Review validates changed paths
  Then it rejects the request before Graph Ops analysis
  And it writes no review artifact

Scenario: reject strict requirement mutations
  Given the Diff-to-Proof Review contract
  When strict validator mutation runs
  Then contract markers include `DIFF_TO_PROOF_REVIEW_V1`, `DIFF_TO_PROOF_INPUTS_EXACT`, `DIFF_TO_PROOF_GRAPH_IMPACT_EXACT`, `DIFF_TO_PROOF_COVERAGE_GAPS_EXPLICIT`, `DIFF_TO_PROOF_RERUN_PLAN_EXACT`, `DIFF_TO_PROOF_UNMATCHED_PRIORITY`, `DIFF_TO_PROOF_MERMAID_EXPORTED`, `DIFF_TO_PROOF_ARTIFACTS_OPTIONAL`, `DIFF_TO_PROOF_NO_EXECUTION`, and `DIFF_TO_PROOF_PATH_REJECTED`
```

## SHOULD — Technical/structural
- ADR references: Graph Ops authority boundary and proof-reuse source binding.
- Data model: change-review record with input source, graph impact, risk plan,
  coverage result, findings, next action, deterministic renderings, and
  optional local artifact hashes.
- API contract: `factory change review --root workspace --base main` with
  repeatable `--changed`, optional `--out-dir`, and `--json`.
- Serialization contract: canonical review hashes use UTF-8 JSON; optional
  review JSON is UTF-8 and two-space (`indent=2`) indented; an optional artifact filename
  uses the `change-review-` prefix plus the first 12 hexadecimal characters of
  the review SHA-256.
- Normalization contract: a workspace-relative `./` prefix is removed before
  sorting and de-duplicating changed paths.

## SHOULD NOT — Implementation details
- Do not create a new risk classifier, hidden proof matcher, agent loop, or
  remote review service. Reuse only the existing Graph Ops, risk-diff, and
  coverage facts.
- Do not call tests, run a replay plan, mutate proof receipts, create a trace,
  or turn absent measurement into a productivity claim.

## Decision logic (factory candidates)
This feature has no HSF business-decision candidate. Findings are ordered by
the following deterministic controller rules: unmatched changed paths first,
then stale proofs, then uncovered requirements, then existing policy reruns,
then a ready-for-human-review notice. All recommendations remain supervised
planning output and never grant execution authority.
