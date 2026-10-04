# TASK PACKET T11 — github-account-overview
<!-- One session. Finish, verify, stop. Context resets after this. -->

## Your single task
Specify and validate account-wide searches, repository attribution, truncation, and visibility boundaries.

## Slice (you may only create/modify files here + tests)
specs

## Files in scope (R_f — read nothing else except context/PROGRESS.md)
- specs/github-account-overview.md
- specs/junie-factoryline-taxonomy-v1.md

## Governing spec excerpt
### Governing requirements (complete blocks)
- Developer or reviewer: receives current repository and change context before acting.
- Host agent: consumes the overview and treats repository-controlled text as untrusted data.
- Repository owner: retains control of credentials and every write operation.
- The system shall return `REQ_GHOV_01` one versioned repository overview through configured agent interfaces.
- When `REQ_GHOV_02` applies to a workspace with a GitHub origin and authenticated CLI session, the system shall return connected-account login, open pull requests and issues visible across repositories, current-origin metadata, recent origin Actions runs/releases, and visible origin rules.
- The system shall apply `REQ_GHOV_03`: read-only remote requests, a 10-second request timeout, validated repository identity, and at most 100 rows per list.
- The system shall return `REQ_GHOV_04` bounded repository inventory, account-wide pull request/issue search, current-origin Actions, releases, rulesets, and visible default-branch policy sections.
- If `REQ_GHOV_13` finds `origin_state` equal to `UNRESOLVED`, the system shall return `UNAVAILABLE_REPOSITORY_UNRESOLVED` without guessing repository identity.
- If `REQ_GHOV_15` finds `policy_visibility` equal to `DENIED` or `UNAVAILABLE`, the system shall return overall `PARTIAL` and preserve that section state.
- The system shall return `REQ_GHOV_18` a bounded repository inventory visible to the connected `gh` session, highlight the workspace origin when it occurs in that inventory, and mark possible truncation without claiming account-wide completeness beyond API visibility.
- The system shall return `REQ_GHOV_19` open pull requests and issues from global GitHub search, include a `repository_url` field on each result, and use provider `total_count` to report truncation even when a response page is incomplete.
- Data model: `factory.github-account-overview.v1` response objects record `cli_state`, `authentication_state`, `origin_state`, `required_api_state`, `policy_visibility`, and `collection_state` using the stated enum values. Every open-work item exposes `repository_url` for repository attribution.
- Provider contract: use GitHub REST HTTP GET via `gh api --method GET`, no shell. Six independent repository inventory, global pull-request search, global issue search, current-origin Actions, current-origin releases, and current-origin ruleset reads run concurrently with at most six workers. Reuse the inventory's repository metadata when it contains the current origin; otherwise fetch origin metadata. Fetch d

## CONSTITUTION DIGEST: one task only; read ONLY listed files; tests ship with code; never touch skeleton/; never add deps without ADR; never leave stubs; decision logic goes to the factory, not inline; stop and ask on ambiguity.

## Definition of done
Run: `rtk proxy python -c "import subprocess,sys; commands=[['specline','validate','github-account-overview','--root','.'],['specline','validate','junie-factoryline-taxonomy-v1','--root','.']]; results=[subprocess.run(c).returncode for c in commands]; raise SystemExit(0 if all(code==0 for code in results) else 1)"` — must pass. Then STOP and report the diff summary.
