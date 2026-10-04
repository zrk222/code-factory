# TASK PACKET T9 — github-account-overview
<!-- One session. Finish, verify, stop. Context resets after this. -->

## Your single task
Search account-visible open PRs/issues across repositories, use provider totals to report truncation, and preserve six-way parallelism.

## Slice (you may only create/modify files here + tests)
factoryline

## Files in scope (R_f — read nothing else except context/PROGRESS.md)
- factoryline/github_account_overview.py
- tests/test_github_account_overview.py

## Governing spec excerpt
### Governing requirements (complete blocks)
- When `REQ_GHOV_02` applies to a workspace with a GitHub origin and authenticated CLI session, the system shall return connected-account login, open pull requests and issues visible across repositories, current-origin metadata, recent origin Actions runs/releases, and visible origin rules.
- The system shall return `REQ_GHOV_04` bounded repository inventory, account-wide pull request/issue search, current-origin Actions, releases, rulesets, and visible default-branch policy sections.
- The system shall return `REQ_GHOV_07` one section state from `AVAILABLE`, `NOT_CONFIGURED`, `PERMISSION_DENIED`, `UNAVAILABLE`, or `TRUNCATED`, and shall not report a missing policy based only on missing access or HTTP 404.
- If `REQ_GHOV_11` finds `cli_state` equal to `MISSING`, the system shall return `UNAVAILABLE_CLI_MISSING` before a provider request.
- If `REQ_GHOV_15` finds `policy_visibility` equal to `DENIED` or `UNAVAILABLE`, the system shall return overall `PARTIAL` and preserve that section state.
- The system shall return `REQ_GHOV_18` a bounded repository inventory visible to the connected `gh` session, highlight the workspace origin when it occurs in that inventory, and mark possible truncation without claiming account-wide completeness beyond API visibility.
- The system shall return `REQ_GHOV_19` open pull requests and issues from global GitHub search, include a `repository_url` field on each result, and use provider `total_count` to report truncation even when a response page is incomplete.
- Data model: `factory.github-account-overview.v1` response objects record `cli_state`, `authentication_state`, `origin_state`, `required_api_state`, `policy_visibility`, and `collection_state` using the stated enum values. Every open-work item exposes `repository_url` for repository attribution.
- Provider contract: use GitHub REST HTTP GET via `gh api --method GET`, no shell. Six independent repository inventory, global pull-request search, global issue search, current-origin Actions, current-origin releases, and current-origin ruleset reads run concurrently with at most six workers. Reuse the inventory's repository metadata when it contains the current origin; otherwise fetch origin metadata. Fetch default-branch protection after repository metadata. Global work searches are limited to the connected identity's GitHub visibility and the requested result bound.
- Read endpoints: `/user/repos`, `/search/issues` with `is:open is:pr`, `/search/issues` with `is:open is:issue`, current-origin `/repos/{owner}/{repo}`, `/actions/r

## CONSTITUTION DIGEST: one task only; read ONLY listed files; tests ship with code; never touch skeleton/; never add deps without ADR; never leave stubs; decision logic goes to the factory, not inline; stop and ask on ambiguity.

## Definition of done
Run: `rtk proxy python -c "import os; os.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1'; import pytest; raise SystemExit(pytest.main(['-p','pytest_asyncio.plugin','-q','tests/test_github_account_overview.py']))"` — must pass. Then STOP and report the diff summary.
