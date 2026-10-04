# TASK PACKET T12 — github-account-overview
<!-- One session. Finish, verify, stop. Context resets after this. -->

## Your single task
Document connected-account search and origin-specific operational detail, including bounds.

## Slice (you may only create/modify files here + tests)
docs

## Files in scope (R_f — read nothing else except context/PROGRESS.md)
- docs/MCP.md

## Governing spec excerpt
### Governing requirements (complete blocks)
- When `REQ_GHOV_02` applies to a workspace with a GitHub origin and authenticated CLI session, the system shall return connected-account login, open pull requests and issues visible across repositories, current-origin metadata, recent origin Actions runs/releases, and visible origin rules.
- The system shall return `REQ_GHOV_04` bounded repository inventory, account-wide pull request/issue search, current-origin Actions, releases, rulesets, and visible default-branch policy sections.
- If `REQ_GHOV_12` finds `authentication_state` equal to `DISCONNECTED`, the system shall return `UNAVAILABLE_NOT_CONNECTED` without another credential source.
- If `REQ_GHOV_13` finds `origin_state` equal to `UNRESOLVED`, the system shall return `UNAVAILABLE_REPOSITORY_UNRESOLVED` without guessing repository identity.
- The system shall return `REQ_GHOV_18` a bounded repository inventory visible to the connected `gh` session, highlight the workspace origin when it occurs in that inventory, and mark possible truncation without claiming account-wide completeness beyond API visibility.
- The system shall return `REQ_GHOV_19` open pull requests and issues from global GitHub search, include a `repository_url` field on each result, and use provider `total_count` to report truncation even when a response page is incomplete.
- Data model: `factory.github-account-overview.v1` response objects record `cli_state`, `authentication_state`, `origin_state`, `required_api_state`, `policy_visibility`, and `collection_state` using the stated enum values. Every open-work item exposes `repository_url` for repository attribution.
- Authentication contract: only the existing `gh auth` session for the host parsed from `origin`; never call `gh auth token`, read token files, or accept a token parameter.
- Provider contract: use GitHub REST HTTP GET via `gh api --method GET`, no shell. Six independent repository inventory, global pull-request search, global issue search, current-origin Actions, current-origin releases, and current-origin ruleset reads run concurrently with at most six workers. Reuse the inventory's repository metadata when it contains the current origin; otherwise fetch origin metadata. Fetch default-branch protection after repository metadata. Global work searches are limited to the connected identity's GitHub visibility and the requested result bound.
- Read endpoints: `/user/repos`, `/search/issues` with `is:open is:pr`, `/search/issues` with `is:open is:issue`, current-origin `/repos/{owner}/{repo}`, `/actions/runs`, `/releases`, `/r

## CONSTITUTION DIGEST: one task only; read ONLY listed files; tests ship with code; never touch skeleton/; never add deps without ADR; never leave stubs; decision logic goes to the factory, not inline; stop and ask on ambiguity.

## Definition of done
Run: `rtk proxy python -c "from pathlib import Path; text=Path('docs/MCP.md').read_text(encoding='utf-8'); assert 'searches open pull requests and issues across GitHub' in text and 'workspace origin' in text and 'total_count' in text"` — must pass. Then STOP and report the diff summary.
