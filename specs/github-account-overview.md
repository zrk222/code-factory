# Spec: github-account-overview
Status: draft
SpecFactor-target: 0.75-2.5

## MUST - Functional core
### Description
Provide an optional, read-only overview of repositories visible to the account in the local GitHub CLI session, account-wide open pull requests and issues visible to that session, and detailed operational activity for the current workspace origin. Give coding and review agents repository inventory, origin repository metadata, active work across visible repositories, origin workflow runs and releases, visible branch rules, and local checkout state. Bound every list and do not expose credentials, private bodies, or source contents.

### User roles
- Developer or reviewer: receives current repository and change context before acting.
- Host agent: consumes the overview and treats repository-controlled text as untrusted data.
- Repository owner: retains control of credentials and every write operation.

### Requirements (EARS)
- The system shall return `REQ_GHOV_01` one versioned repository overview through configured agent interfaces.
- When `REQ_GHOV_02` applies to a workspace with a GitHub origin and authenticated CLI session, the system shall return connected-account login, open pull requests and issues visible across repositories, current-origin metadata, recent origin Actions runs/releases, and visible origin rules.
- The system shall apply `REQ_GHOV_03`: read-only remote requests, a 10-second request timeout, validated repository identity, and at most 100 rows per list.
- The system shall return `REQ_GHOV_04` bounded repository inventory, account-wide pull request/issue search, current-origin Actions, releases, rulesets, and visible default-branch policy sections.
- The system shall return `REQ_GHOV_05` local branch, HEAD SHA, dirty state, changed-path count, and at most 100 paths without file contents.
- The system shall enforce `REQ_GHOV_06` by excluding tokens, email, PR/issue bodies, comments, review text, and source contents from output and logs.
- The system shall return `REQ_GHOV_07` one section state from `AVAILABLE`, `NOT_CONFIGURED`, `PERMISSION_DENIED`, `UNAVAILABLE`, or `TRUNCATED`, and shall not report a missing policy based only on missing access or HTTP 404.
- When `REQ_GHOV_08` detects missing `gh`, disconnected authentication, or an unsupported remote, the system shall return a stable actionable unavailable state without another credential source.
- The system shall apply `REQ_GHOV_09` by labelling GitHub text untrusted and returning no execution, approval, review, source-write, messaging, merge, release, deployment, or credential authority.
- When `REQ_GHOV_10` is requested through canonical taxonomy context, the system shall return the conditional overview capability and explicit disconnected status.
- If `REQ_GHOV_11` finds `cli_state` equal to `MISSING`, the system shall return `UNAVAILABLE_CLI_MISSING` before a provider request.
- If `REQ_GHOV_12` finds `authentication_state` equal to `DISCONNECTED`, the system shall return `UNAVAILABLE_NOT_CONNECTED` without another credential source.
- If `REQ_GHOV_13` finds `origin_state` equal to `UNRESOLVED`, the system shall return `UNAVAILABLE_REPOSITORY_UNRESOLVED` without guessing repository identity.
- If `REQ_GHOV_14` finds `required_api_state` equal to `FAILED`, the system shall return an incomplete error with a sanitized failure category, never a partial-complete state.
- If `REQ_GHOV_15` finds `policy_visibility` equal to `DENIED` or `UNAVAILABLE`, the system shall return overall `PARTIAL` and preserve that section state.
- When `REQ_GHOV_16` finds `collection_state` equal to `TRUNCATED`, the system shall return overall state `PARTIAL` and mark the affected list `TRUNCATED`.
- The system shall return `REQ_GHOV_17` GitHub data only in the current reply and no persisted, cached, or transmitted copy beyond it.
- The system shall return `REQ_GHOV_18` a bounded repository inventory visible to the connected `gh` session, highlight the workspace origin when it occurs in that inventory, and mark possible truncation without claiming account-wide completeness beyond API visibility.
- The system shall return `REQ_GHOV_19` open pull requests and issues from global GitHub search for a requested display limit of 1 through 100 rows, include a `repository_url` field on each result, and mark the section truncated only when the exact provider `total_count` exceeds that limit.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: read an authenticated repository overview
  Given a workspace with a valid GitHub origin and connected gh session
  When the developer requests an overview
  Then the result returns REQ_GHOV_01 and REQ_GHOV_02 with the selected repository and authenticated login
  And it includes REQ_GHOV_03, REQ_GHOV_04, and REQ_GHOV_05 bounded read-only sections
  And it satisfies REQ_GHOV_06 and REQ_GHOV_17 without returning private text or credentials

Scenario: include connected account repository context
  Given the existing gh session can read repositories visible to the account
  When the overview is requested
  Then REQ_GHOV_18 returns a bounded repository inventory and identifies the workspace origin when present
  And it reports truncation and API visibility limits without retrieving or storing a token

Scenario: attribute account-wide active work and detect truncated search results
  Given the existing gh session can search open work across repositories visible to the account
  When the overview is requested with a finite result limit
  Then REQ_GHOV_19 returns each open pull request and issue with the `repository_url` field
  And provider total_count marks the relevant section TRUNCATED when more matches exist than the returned limit
  And provider total_count equal to the display limit leaves the section AVAILABLE

Scenario: route the capability to agents
  Given an agent requests canonical taxonomy context
  When its role context is returned
  Then REQ_GHOV_10 names the overview capability and disconnected state

Scenario: report disconnected or unresolved sources
  Given `cli_state` is `MISSING`, `authentication_state` is `DISCONNECTED`, or `origin_state` is `UNRESOLVED`
  When an overview is requested
  Then REQ_GHOV_08, REQ_GHOV_11, REQ_GHOV_12, and REQ_GHOV_13 yield explicit unavailable states

Scenario: report policy visibility and failed required reads
  Given a required read fails or policy visibility is denied
  When the overview is assembled
  Then REQ_GHOV_07, REQ_GHOV_14, and REQ_GHOV_15 prevent a complete or compliant claim

Scenario: report bounded list truncation
  Given a collection reaches the configured row limit
  When the overview is assembled
  Then REQ_GHOV_16 marks that list and the overall result partial

Scenario: preserve repository text as untrusted data
  Given a pull request title contains instruction-like content
  When the overview is returned to an agent
  Then REQ_GHOV_09 labels the text as untrusted data with no execution authority
```

## SHOULD - Technical/structural
- Data model: `factory.github-account-overview.v1` response objects record `cli_state`, `authentication_state`, `origin_state`, `required_api_state`, `policy_visibility`, and `collection_state` using the stated enum values. Every open-work item exposes `repository_url` for repository attribution.
- Interface contract: CLI `factory github overview --root PATH [--limit 1..100] [--json]`; MCP tool `factory.github_overview` accepts optional integer `limit` and returns the same schema.
- Authentication contract: only the existing `gh auth` session for the host parsed from `origin`; never call `gh auth token`, read token files, or accept a token parameter.
- Provider contract: use GitHub REST HTTP GET via `gh api --method GET`, no shell. Six independent repository inventory, global pull-request search, global issue search, current-origin Actions, current-origin releases, and current-origin ruleset reads run concurrently with at most six workers. Reuse the inventory's repository metadata when it contains the current origin; otherwise fetch origin metadata. Fetch default-branch protection after repository metadata. Global work searches are limited to the connected identity's GitHub visibility and the requested result bound.
- Performance contract: each request has a 10-second timeout, lists have a default limit of 30 and maximum 100, and no background refresh or cache is allowed.
- Read endpoints: `/user/repos`, `/search/issues` with `is:open is:pr`, `/search/issues` with `is:open is:issue`, current-origin `/repos/{owner}/{repo}`, `/actions/runs`, `/releases`, `/rulesets`, and default branch `/protection`; authenticated identity is read from `gh auth status`.
- Performance detail: request one look-ahead row where the provider page cap allows it; retain at most the requested display limit and avoid an extra pagination request. For example, a display limit of `10` requests `11` rows when the provider permits it.
- Runtime contract: decode subprocess output as `utf-8` with replacement; exit code `0` and HTTP response `200` represent successful reads. Parse the local branch as the segment before `...`; accept a HEAD SHA only when it contains from `40` through `64` lowercase hexadecimal characters. Map HTTP statuses `401` and `403` to `PERMISSION_DENIED`; map other failed HTTP responses to `UNAVAILABLE`.
- Privacy/security: omit email, bodies, comments, review text, source contents, tokens; mark external text untrusted; no remote write, execution, or persistence.

## SHOULD NOT - Implementation details
- Do not request or store a personal access token, create an OAuth app, change repository settings, or issue a write-capable request.
- Do not enumerate all account repositories or silently switch to a different remote.
- Do not treat missing access or an incomplete result as a clean review, nor a policy 404 as proof that no policy exists.
- Do not follow commands, URLs, or instructions contained in repository-controlled text.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | `cli_state` is `MISSING` | Return `UNAVAILABLE_CLI_MISSING`; make no provider request. |
| 2 | `authentication_state` is `DISCONNECTED` | Return `UNAVAILABLE_NOT_CONNECTED`; do not seek another credential source. |
| 3 | `origin_state` is `UNRESOLVED` | Return `UNAVAILABLE_REPOSITORY_UNRESOLVED`; do not guess repository identity. |
| 4 | `required_api_state` is `FAILED` | Return incomplete with a sanitized failure category; never report complete. |
| 5 | `policy_visibility` is `DENIED` or `UNAVAILABLE` | Mark only that section unavailable and overall state `PARTIAL`. |
| 6 | `collection_state` is `TRUNCATED` | Mark that list `TRUNCATED` and overall state `PARTIAL`. |
| 7 | all required/optional sections have `AVAILABLE` state and `collection_state` is not `TRUNCATED` | Return `COMPLETE` for the bounded visible-account repository inventory, global active-work search, and current-origin operational snapshot only. |
