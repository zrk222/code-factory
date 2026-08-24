# Spec: jetbrains-repair-sandbox
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core
### Description
Provide a native JetBrains **Verified Repair Sandbox** for professional teams.
It shall convert one explicitly selected local Change List into a hash-bound
Scope Passport, accept only a textual candidate patch whose paths stay inside
that scope, and make independent verification plus human diff application
visible requirements. It must never become a silent code editor, model runner,
test runner, commit action, or release gate.

### User roles
- Developer: isolates one task from a busy working tree before using an
  external supervised repair assistant.
- Reviewer: checks that a candidate patch did not cross the agreed Change List.
- Engineering lead: receives a durable local scope/candidate handoff with
  explicit validation and ownership boundaries.

### Requirements (EARS)
- The system shall emit `REPAIR_SANDBOX_TAB_AVAILABLE` only when the FactoryLine tool window contains a startable Repair Sandbox tab that explains its no-implicit-runner and human-apply boundary.
- When a developer selects a native non-empty Change List and confirms the local command, the system shall emit `REPAIR_SCOPE_CONFIRMATION_REQUIRED` before running only `factory repair scope` with one explicit `--change-list`, one through fifty explicit `--changed` paths, `--json`, and a local artifact directory below `.factory/repair-sandboxes`.
- If scope construction receives valid explicit paths, the system shall emit `REPAIR_SCOPE_HASH_BOUND`, return schema `factory.repair_scope.v1`, bind the selected Change List name, current file-or-deletion baselines, the existing Change Review hash and fact-derived next action, and an all-false external-effect authority object.
- When a scope is prepared, the system shall emit `REPAIR_CONTEXT_BYTES_EXACT` with its exact current file count and byte total against a caller-selected threshold from 1 through 100,000,000 bytes. It shall return `split_recommended` only when measured bytes exceed that threshold, and it shall not infer tokens, provider credits, latency, or quality from those bytes.
- When a selected scope is saved, the system shall emit `REPAIR_SCOPE_ARTIFACTS_WRITTEN` only after writing JSON, Markdown, and Mermaid artifacts beneath the selected workspace directory; it shall not upload them or create a candidate worktree.
- When a developer selects a candidate patch inside the workspace and confirms the local command, the system shall emit `REPAIR_CANDIDATE_CONFIRMATION_REQUIRED` before running only `factory repair candidate` with the saved scope packet, patch, local artifact directory, and `--json`.
- If a candidate patch contains one or more standard UTF-8 textual Git diff headers and every declared old, new, or rename path is in the sealed scope, the system shall emit `REPAIR_CANDIDATE_PATCH_SCOPED`, return schema `factory.repair_candidate.v1`, bind the patch bytes to the current scope SHA-256, and require independent verifier evidence and human confirmation.
- If a scope baseline drifts, the scope digest is malformed, a path escapes the workspace, or a candidate patch contains an outside, combined, binary, or unsupported quoted path, the system shall emit `REPAIR_SANDBOX_UNAVAILABLE` with the redacted CLI failure; it shall not show a pass or eligible-to-apply result.
- If a candidate patch declares a path outside the sealed Change List, the CLI shall return code `REPAIR_CANDIDATE_OUT_OF_SCOPE` and no candidate artifact, source edit, test, or network action.
- The system shall emit `REPAIR_SANDBOX_HUMAN_APPLY_REQUIRED` and never apply a candidate patch, edit source, run a test, commit, merge, publish, deploy, sign, access credentials, or call a network service while preparing or inspecting a repair candidate.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: prepare one professional Change List scope
  Given a project has several Change Lists with related local source changes
  When the developer selects one non-empty Change List and confirms Prepare Change List
  Then FactoryLine sends only that list's explicit workspace-relative paths to factory repair scope
  And it writes a local Scope Passport with JSON Markdown and Mermaid evidence
  And unrelated Change List paths are absent
  And its Context Budget shows measured bytes without a token or credit saving claim

Scenario: accept only a scope-bound candidate patch
  Given a current Scope Passport for src/service.py
  And an external supervised runner saved a textual candidate patch for src/service.py
  When the developer confirms Validate Candidate Patch
  Then FactoryLine binds the patch SHA-256 to the scope SHA-256
  And it requires independent verification and a human apply decision
  And it does not apply the patch or run a test

Scenario: reject a patch outside the sealed scope
  Given a Scope Passport for src/service.py
  When a candidate patch also changes .github/workflows/publish.yml
  Then FactoryLine returns REPAIR_CANDIDATE_OUT_OF_SCOPE
  And the Repair Sandbox shows an unavailable state
  And no source, test, commit, or network action occurs

Scenario: reject strict requirement mutations
  Given the Verified Repair Sandbox contract
  When strict validator mutation runs
  Then contract markers include `REPAIR_SANDBOX_TAB_AVAILABLE`, `REPAIR_SCOPE_CONFIRMATION_REQUIRED`, `REPAIR_SCOPE_HASH_BOUND`, `REPAIR_CONTEXT_BYTES_EXACT`, `REPAIR_SCOPE_ARTIFACTS_WRITTEN`, `REPAIR_CANDIDATE_CONFIRMATION_REQUIRED`, `REPAIR_CANDIDATE_PATCH_SCOPED`, `REPAIR_SANDBOX_UNAVAILABLE`, and `REPAIR_SANDBOX_HUMAN_APPLY_REQUIRED`
```

## SHOULD - Technical/structural
- Reuse `factory change review` as the source of proof-gap and risk facts; do
  not create a second proof classifier.
- Use `ChangeListManager` and `LocalChangeList` only for selecting exact native
  local paths. Files outside the project root, directories, and unresolvable
  Change objects must block the prepared scope rather than being silently lost.
- Parse only stable scope/candidate JSON schemas in the Kotlin adapter; unknown
  JSON is an unavailable state.
- Candidate patch validation supports standard unquoted textual Git diff
  headers in the first release. It fail-closes combined, binary, quoted, and
  out-of-scope forms rather than guessing how an eventual patch application
  would behave.

## SHOULD NOT - Implementation details
- Do not invoke JetBrains AI Assistant, a model, MCP server, GitHub API, shell,
  remote service, PSI inspection, VCS commit, or automatic patch apply.
- Do not claim that scope preparation, patch scoping, or a verifier receipt
  proves quality, security, runtime isolation, or release readiness.
