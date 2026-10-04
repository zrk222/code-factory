# TASK PACKET T1 — github-account-overview
<!-- One session. Finish, verify, stop. Context resets after this. -->

## Your single task
Implement the bounded, sanitized GET-only provider snapshot and negative/boundary tests.

## Slice (you may only create/modify files here + tests)
factoryline

## Files in scope (R_f — read nothing else except context/PROGRESS.md)
- factoryline/github_account_overview.py
- tests/test_github_account_overview.py

## Governing spec excerpt
### Governing requirements (complete blocks)
- The system shall apply `REQ_GHOV_03`: read-only remote requests, a 10-second request timeout, validated repository identity, and at most 100 rows per list.
- The system shall return `REQ_GHOV_04` bounded repository, pull request/issue, Actions, release, ruleset, and visible default-branch policy sections.
- The system shall return `REQ_GHOV_07` one section state from `AVAILABLE`, `NOT_CONFIGURED`, `PERMISSION_DENIED`, `UNAVAILABLE`, or `TRUNCATED`, and shall not report a missing policy based only on missing access or HTTP 404.
- If `REQ_GHOV_11` finds `cli_state` equal to `MISSING`, the system shall return `UNAVAILABLE_CLI_MISSING` before a provider request.
- If `REQ_GHOV_14` finds `required_api_state` equal to `FAILED`, the system shall return an incomplete error with a sanitized failure category, never a partial-complete state.
- The system shall return `REQ_GHOV_17` GitHub data only in the current reply and no persisted, cached, or transmitted copy beyond it.
- Authentication contract: only the existing `gh auth` session for the host parsed from `origin`; never call `gh auth token`, read token files, or accept a token parameter.
- Provider contract: use GitHub REST HTTP GET via `gh api --method GET`, no shell. Independent identity, repository, pull/issue, Actions, release, and ruleset reads run concurrently with at most six workers. Fetch default-branch protection after repository metadata.

### Acceptance (verbatim — do not reinterpret)
```gherkin
Scenario: read an authenticated repository overview
  Given a workspace with a valid GitHub origin and connected gh session
  When the developer requests an overview
  Then the result returns REQ_GHOV_01 and REQ_GHOV_02 with the selected repository and authenticated login
  And it includes REQ_GHOV_03, REQ_GHOV_04, and REQ_GHOV_05 bounded read-only sections
  And it satisfies REQ_GHOV_06 and REQ_GHOV_17 without returning private text or credentials

Scenario: route the capability to agents
  Given an agent requests canonical taxonomy context
  When its role context is returned
  Then REQ_GHOV_10 names the overview capability and disconnected state

Scenario: report disconnected or unresolved sources
  Given `cli_state` is `MISSING`, `authentication_state` is `DISCONNECTED`, or `origin_state` is `UNRESOLVED`
  When an overview is requested
  Then REQ_GHOV_08, REQ_GHOV_11, REQ_GHOV_12, and REQ_GHOV_13 yield explicit unavailable states

## CONSTITUTION DIGEST: one task only; read ONLY listed files; tests ship with code; never touch skeleton/; never add deps without ADR; never leave stubs; decision logic goes to the factory, not inline; stop and ask on ambiguity.

## Definition of done
Run: `rtk proxy python -m pytest tests/test_github_account_overview.py -q` — must pass. Then STOP and report the diff summary.
