# Diff-to-Proof Review

`factory change review` gives one deterministic answer to the question a
developer asks after a real diff: **what did this change affect, what evidence
is stale or missing, and what is the smallest defensible next review action?**

```powershell
factory change review --root . --base origin/main --json
factory change review --root . --changed factoryline/graph_ops.py --out-dir .factory/change-reviews
factory change scope-check --root . --base origin/main --json
```

The command joins only existing local facts:

- Git changed paths, unless explicit `--changed` paths are supplied;
- exact Graph Ops proof-input impact and stale-proof state;
- requirement coverage facts, including missing coverage manifests;
- the existing risk-diff policy's **plan-only** rerun stages.

It returns JSON, deterministic Markdown, and a Mermaid map. With no `--out-dir`
it writes nothing. An explicit output directory writes only local review JSON,
Markdown, and Mermaid artifacts beneath that chosen directory.

## Repository product-boundary guard

Use `factory change scope-check` when a repository needs to prevent source or
documentation for a separately owned product from entering its pull requests.
Define reserved path-name segments in `.factory/repository-scope.json`:

```json
{
  "schema": "factory.repository_scope.v1",
  "blocked_path_segments": ["agent-oven", "private-product"]
}
```

Reserve a top-level namespace root such as `products` when the repository must
reject entire product subtrees, including products whose names are not yet
known. This reserves only that root; ordinary files such as `docs/products.md`
remain allowed.

The checker normalizes case, camel-case names, spaces, underscores, and
punctuation, and checks path components and filenames. For example,
`AgentOvenServer.ts` matches the reserved `agent-oven` segment. Added, modified,
copied, renamed, or type-changed paths that match a reserved segment return
exit code `2` with `REPOSITORY_SCOPE_BLOCKED` and exact paths. Copies and
renames check both the source and destination. Deletions are permitted, so
teams can remove an accidental product import. Invalid or missing policy and
Git diff errors fail closed. This is a path boundary guard, not semantic source
classification; choose names that identify the product reliably.

When the policy exists, the regular `factory change review` packet also places
violations first in its findings and gives the removal action. Missing policy
is shown as `not_configured`; malformed or unreadable configured policy is a
blocking finding. The standalone `scope-check` is useful for an enforcing CI
step because it returns a failing exit code directly.

For automatic PR enforcement, use a `pull_request_target` workflow already
present on the protected target branch. Check out only the base commit, fetch
the PR head as a Git ref without checking out or running its files, and run the
CLI from the base checkout:

```yaml
- name: Enforce repository product boundaries
  env:
    PR_NUMBER: ${{ github.event.pull_request.number }}
    PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}
    PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}
  run: |
    git fetch --no-tags origin "+refs/pull/${PR_NUMBER}/head:refs/remotes/origin/pr/${PR_NUMBER}"
    test "$(git rev-parse "refs/remotes/origin/pr/${PR_NUMBER}^{commit}")" = "$PR_HEAD_SHA"
    factory change scope-check --root . --base "$PR_BASE_SHA" \
      --head "$PR_HEAD_SHA" --policy-ref "$PR_BASE_SHA" --json
```

The workflow and CLI must come from the base commit, and the scope policy must
be read from that same commit. Require the `repository-scope-guard` status check
in branch protection. The Code Factory repository supplies
`.github/workflows/repository-scope-guard.yml`; it inspects Git metadata only
and does not execute candidate code. Its existing `pull_request` proof workflow
also emits a scope report for visibility, but is not the trusted enforcement
root. When first installing this guard, the initial policy/workflow change
requires independent review; the protected workflow enforces later PRs after it
is present on the target branch.

## Optional GitHub pull-request surface

For a team that wants the same deterministic facts visible beside an AI or
human review, `factory github proof-review` validates the current review's
SHA-256 and renders one neutral Check/comment payload tied to an exact commit.
Its opt-in workflow can coexist with CodeRabbit or another reviewer; it neither
requires their account nor treats their output as proof. See
[GitHub Proof Review](GITHUB_PROOF_REVIEW.md).

## What it never does

Diff-to-Proof Review does not run tests or a replay plan. It does not modify
source, create a trace, merge, publish, deploy, sign, send messages, access
credentials, or grant connectors. A recommendation is not evidence that a
command ran; an unmatched changed path, stale proof, and missing coverage stay
visible until independently resolved.
