# TASK PACKET T10 — github-account-overview
<!-- One session. Finish, verify, stop. Context resets after this. -->

## Your single task
Expose account-visible active-work scope and origin-scoped operational data to MCP and all agent roles.

## Slice (you may only create/modify files here + tests)
factoryline

## Files in scope (R_f — read nothing else except context/PROGRESS.md)
- factoryline/mcp.py
- factoryline/audit_taxonomy.py
- factoryline/junie_taxonomy.py
- tests/test_mcp.py

## Governing spec excerpt
### Governing requirements (complete blocks)
- Host agent: consumes the overview and treats repository-controlled text as untrusted data.
- The system shall return `REQ_GHOV_01` one versioned repository overview through configured agent interfaces.
- When `REQ_GHOV_02` applies to a workspace with a GitHub origin and authenticated CLI session, the system shall return connected-account login, open pull requests and issues visible across repositories, current-origin metadata, recent origin Actions runs/releases, and visible origin rules.
- The system shall return `REQ_GHOV_04` bounded repository inventory, account-wide pull request/issue search, current-origin Actions, releases, rulesets, and visible default-branch policy sections.
- If `REQ_GHOV_13` finds `origin_state` equal to `UNRESOLVED`, the system shall return `UNAVAILABLE_REPOSITORY_UNRESOLVED` without guessing repository identity.
- The system shall return `REQ_GHOV_17` GitHub data only in the current reply and no persisted, cached, or transmitted copy beyond it.
- The system shall return `REQ_GHOV_18` a bounded repository inventory visible to the connected `gh` session, highlight the workspace origin when it occurs in that inventory, and mark possible truncation without claiming account-wide completeness beyond API visibility.
- Data model: `factory.github-account-overview.v1` response objects record `cli_state`, `authentication_state`, `origin_state`, `required_api_state`, `policy_visibility`, and `collection_state` using the stated enum values. Every open-work item exposes `repository_url` for repository attribution.
- Authentication contract: only the existing `gh auth` session for the host parsed from `origin`; never call `gh auth token`, read token files, or accept a token parameter.
- Provider contract: use GitHub REST HTTP GET via `gh api --method GET`, no shell. Six independent repository inventory, global pull-request search, global issue search, current-origin Actions, current-origin releases, and current-origin ruleset reads run concurrently with at most six workers. Reuse the inventory's repository metadata when it contains the current origin; otherwise fetch origin metadata. Fetch default-branch protection after repository metadata. Global work searches are limited to the connected identity's GitHub visibility and the requested result bound.
- Read endpoints: `/user/repos`, `/search/issues` with `is:open is:pr`, `/search/issues` with `is:open is:issue`, current-origin `/repos/{owner}/{repo}`, `/actions/runs`, `/releases`, `/rulesets`, and default branch `/protection`; authenticated id

## CONSTITUTION DIGEST: one task only; read ONLY listed files; tests ship with code; never touch skeleton/; never add deps without ADR; never leave stubs; decision logic goes to the factory, not inline; stop and ask on ambiguity.

## Definition of done
Run: `rtk proxy python -c "import os; os.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1'; import pytest; raise SystemExit(pytest.main(['-p','pytest_asyncio.plugin','-q','tests/test_mcp.py','tests/test_junie_taxonomy.py']))"` — must pass. Then STOP and report the diff summary.
