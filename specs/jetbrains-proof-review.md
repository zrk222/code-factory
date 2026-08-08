# Spec: jetbrains-proof-review
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core
### Description
Provide a native JetBrains **Proof Review** tab for a developer reviewing a
real local diff. It must turn the existing deterministic `factory change
review` result into a concise, navigable review surface: changed files, the
single fact-derived next action, explicit proof findings, and unproven claims.
It must preserve the CLI as the only evidence authority and must never become
an autonomous code editor, LLM reviewer, or release gate.

### User roles
- Developer: reviews a current branch plus working-tree diff before asking a
  teammate to review or committing.
- Reviewer: opens an exact changed path from a stated proof gap without
  reconstructing the command output by hand.
- Engineering lead: sees a visible boundary between a recommendation and an
  executed verification result.

### Requirements (EARS)
- The system shall emit `PROOF_REVIEW_TAB_AVAILABLE` only when a second non-closable Proof Review content tab exists in the FactoryLine tool window and its initial state says local, analysis-only, and explicit-command-only.
- When the user selects Review current diff, the system shall emit `PROOF_REVIEW_CONFIRMATION_REQUIRED` before returning the direct result of factory change review --root . --json in the current project root, never through a shell.
- When a project file is active in an editor, the system shall emit `PROOF_REVIEW_ACTIVE_FILE_SCOPE` before returning the direct result of factory change review --root . --changed src/service.py --json without unrelated Git paths in that focused review.
- If the confirmed command response schema equals factory.change_review.v1, the system shall emit `PROOF_REVIEW_STRUCTURED_RESULT` and render only the review hash, changed paths, fact-derived next action, findings, unproven claims, and analysis-only authority boundary.
- If the command returns a non-zero exit, reaches the existing 300 seconds command boundary, or returns an unknown schema, the system shall emit `PROOF_REVIEW_UNAVAILABLE` and render a visible unavailable state with captured redacted output, never a pass, ready-to-ship result, or synthesized finding.
- When the structured result contains changed paths, the system shall emit `PROOF_REVIEW_PATH_NAVIGATION_BOUND` and open a selected path only when it resolves inside the project, never creating a file, opening an external path, or inferring a source range.
- The system shall emit `PROOF_REVIEW_ATTENTION_FIRST` and render blocking and required findings above review and informational findings, label every result analysis-only, and copy a concise redacted review brief only to the local clipboard.
- When the user selects Save review handoff, the system shall request a second local-workspace confirmation. After the user chooses Run local command, it shall invoke factory change review --root . --out-dir .factory/change-reviews --json and emit `PROOF_REVIEW_HANDOFF_SAVED` when the structured response lists JSON, Markdown, and Mermaid artifact paths under the current project.
- When no explicit changed path is supplied, the system shall emit `PROOF_REVIEW_LOCAL_SCOPE_UNION` and return the sorted union of paths changed in BASE...HEAD, unstaged paths, staged paths, and non-ignored untracked paths, or reject a Git failure with no review packet.
- The system shall emit `PROOF_REVIEW_EXPLICIT_SCOPE` and return an explicit changed input as the entire review scope while skipping every Git query.
- The system shall emit `PROOF_REVIEW_FACTS_PRESERVED` and return the existing 1 through 50 normalized workspace-relative path bound, exact Graph Ops impact facts, coverage facts, plan-only rerun recommendations, and all-false external-effect authority object from factory.change_review.v1.
- The system shall emit `PROOF_REVIEW_NO_AUTONOMY` and execute no network client, project-data send, LLM request, source modification, diff application, test, commit, or before-commit blocker while performing Proof Review; an explicitly confirmed handoff command may write only its three local review artifacts under .factory/change-reviews.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: review a real local diff in the IDE
  Given a project with a changed file and FactoryLine proof inputs
  When the developer confirms Review current diff
  Then FactoryLine runs only factory change review with JSON output
  And the Proof Review tab shows a next action, findings, and changed paths
  And no test, replay plan, source edit, or network request occurs

Scenario: include working tree paths when reviewing without explicit paths
  Given a Git workspace with paths in a branch diff, index, working tree, and untracked files
  When factory change review runs without --changed
  Then its changed_paths are the sorted de-duplicated union of those paths
  And input_source is git

Scenario: retain an explicit path scope
  Given a Git workspace with unrelated local changes
  When factory change review receives --changed src/only.py
  Then changed_paths contains only src/only.py
  And the command performs no Git query

Scenario: focus an evidence review on the active editor file
  Given src/service.py is the active project file and the working tree has unrelated changes
  When the developer confirms Review this file
  Then FactoryLine requests a review with --changed src/service.py
  And the Proof Review tab contains no unrelated Git path
  And the result remains analysis-only

Scenario: create a local review handoff packet by explicit choice
  Given a completed Proof Review in a local project
  When the developer confirms Save review handoff
  Then FactoryLine writes only JSON Markdown and Mermaid review artifacts below .factory/change-reviews
  And the result includes their project-contained paths and hashes
  And it does not send the packet or modify source code

Scenario: expose an unavailable review honestly
  Given a project without an available review base
  When the developer confirms Review current diff
  Then the Proof Review tab shows the command failure
  And it does not show a success, a release decision, or invented proof data

Scenario: navigate only to a workspace file
  Given a structured review containing src/service.py
  When the developer opens the selected changed path
  Then IntelliJ opens that existing project file
  And a parent-traversal or missing path is refused

Scenario: reject strict requirement mutations
  Given the JetBrains Proof Review contract
  When strict validator mutation runs
  Then contract markers include `PROOF_REVIEW_TAB_AVAILABLE`, `PROOF_REVIEW_CONFIRMATION_REQUIRED`, `PROOF_REVIEW_ACTIVE_FILE_SCOPE`, `PROOF_REVIEW_STRUCTURED_RESULT`, `PROOF_REVIEW_UNAVAILABLE`, `PROOF_REVIEW_PATH_NAVIGATION_BOUND`, `PROOF_REVIEW_ATTENTION_FIRST`, `PROOF_REVIEW_HANDOFF_SAVED`, `PROOF_REVIEW_LOCAL_SCOPE_UNION`, `PROOF_REVIEW_EXPLICIT_SCOPE`, `PROOF_REVIEW_FACTS_PRESERVED`, and `PROOF_REVIEW_NO_AUTONOMY`
```

## SHOULD - Technical/structural
- ADR references: `docs/JETBRAINS_CONTROL_ROOM.md` and
  `docs/DIFF_TO_PROOF_REVIEW.md` authority boundaries.
- Data model: a Kotlin parser limited to stable `factory.change_review.v1`
  fields and a path-list model; it retains raw, redacted output only for
  progressive disclosure or failure diagnosis.
- Serialization contract: the command response is UTF-8 JSON emitted only by
  `factory change review --json`; unknown JSON schemas are unavailable states.
- API contract: the IDE invokes the existing CLI command with `--json`; it
  adds no JetBrains API service, remote endpoint, or persistent daemon.
- UI contract: follow JetBrains tool-window guidance with a short tab name,
  startable empty state, a compact attention-first summary, path navigation,
  focused-file review, and locally copyable brief; detailed raw output remains
  secondary.
- Execution contract: the command remains a visible, cancellable background
  task and uses direct executable invocation.

## SHOULD NOT - Implementation details
- Do not depend on JetBrains AI Assistant, a paid JetBrains product, a GitHub
  API, an external LLM, PSI-based findings, inspections, or a private platform
  API.
- Do not turn a source path into a line-level problem, gutter marker, or SARIF
  finding before the CLI supplies a validated location-bearing contract.
- Do not silently include ignored files or exceed the existing 50-path review
  bound.

## Decision logic (factory candidates)
This feature reuses the existing deterministic Diff-to-Proof ordering: an
unmatched changed path precedes stale proof, incomplete coverage, plan-only
rerun, and ready-for-human-review. The JetBrains adapter displays that result
and does not add a new classifier or HSF decision candidate.
