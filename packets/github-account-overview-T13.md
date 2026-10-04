# TASK PACKET T13 — github-account-overview
<!-- One session. Finish, verify, stop. Context resets after this. -->

## Your single task
Use provider exact totals to distinguish exactly-at-limit global search results from results proven to exceed the limit.

## Slice (you may only create/modify files here + tests)
factoryline

## Files in scope (R_f — read nothing else except context/PROGRESS.md)
- factoryline/github_account_overview.py
- tests/test_github_account_overview.py

## Governing spec excerpt
### Governing requirements (complete blocks)
- The system shall return `REQ_GHOV_04` bounded repository inventory, account-wide pull request/issue search, current-origin Actions, releases, rulesets, and visible default-branch policy sections.
- The system shall enforce `REQ_GHOV_06` by excluding tokens, email, PR/issue bodies, comments, review text, and source contents from output and logs.
- The system shall return `REQ_GHOV_07` one section state from `AVAILABLE`, `NOT_CONFIGURED`, `PERMISSION_DENIED`, `UNAVAILABLE`, or `TRUNCATED`, and shall not report a missing policy based only on missing access or HTTP 404.
- If `REQ_GHOV_11` finds `cli_state` equal to `MISSING`, the system shall return `UNAVAILABLE_CLI_MISSING` before a provider request.
- The system shall return `REQ_GHOV_19` open pull requests and issues from global GitHub search for a requested display limit of 1 through 100 rows, include a `repository_url` field on each result, and mark the section truncated only when the exact provider `total_count` exceeds that limit.
- Interface contract: CLI `factory github overview --root PATH [--limit 1..100] [--json]`; MCP tool `factory.github_overview` accepts optional integer `limit` and returns the same schema.
- Authentication contract: only the existing `gh auth` session for the host parsed from `origin`; never call `gh auth token`, read token files, or accept a token parameter.
- Provider contract: use GitHub REST HTTP GET via `gh api --method GET`, no shell. Six independent repository inventory, global pull-request search, global issue search, current-origin Actions, current-origin releases, and current-origin ruleset reads run concurrently with at most six workers. Reuse the inventory's repository metadata when it contains the current origin; otherwise fetch origin metadata. Fetch default-branch protection after repository metadata. Global work searches are limited to the connected identity's GitHub visibility and the requested result bound.
- Performance contract: each request has a 10-second timeout, lists have a default limit of 30 and maximum 100, and no background refresh or cache is allowed.
- Read endpoints: `/user/repos`, `/search/issues` with `is:open is:pr`, `/search/issues` with `is:open is:issue`, current-origin `/repos/{owner}/{repo}`, `/actions/runs`, `/releases`, `/rulesets`, and default branch `/protection`; authenticated identity is read from `gh auth status`.
- Performance detail: request one look-ahead row where the provider page cap allows it; retain at most the requested display limit and avoid an extra pagination request. Fo

## CONSTITUTION DIGEST: one task only; read ONLY listed files; tests ship with code; never touch skeleton/; never add deps without ADR; never leave stubs; decision logic goes to the factory, not inline; stop and ask on ambiguity.

## Definition of done
Run: `rtk proxy python -c "import os; os.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1'; import pytest; raise SystemExit(pytest.main(['-p','pytest_asyncio.plugin','-q','tests/test_github_account_overview.py']))"` — must pass. Then STOP and report the diff summary.
