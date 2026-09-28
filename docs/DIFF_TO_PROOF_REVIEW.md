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

The checker normalizes case, spaces, underscores, and punctuation, and checks
path components and filenames. Added, modified, copied, renamed-to, and
type-changed paths that match a reserved segment return exit code `2` with
`REPOSITORY_SCOPE_BLOCKED` and exact paths. Deletions are permitted, so teams
can remove an accidental product import. Invalid or missing policy and Git
diff errors fail closed. This is a path boundary guard, not semantic source
classification; choose names that identify the product reliably.

When the policy exists, the regular `factory change review` packet also places
violations first in its findings and gives the removal action. Missing policy
is shown as `not_configured`; malformed or unreadable configured policy is a
blocking finding. The standalone `scope-check` is useful for an enforcing CI
step because it returns a failing exit code directly.

For automatic PR enforcement, run the same CLI after checkout and installation
of Code Factory. Fetch the PR base at full depth and pass its immutable SHA as
both the diff base and trusted policy revision:

```yaml
- name: Enforce repository product boundaries
  env:
    PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}
  run: >-
    factory change scope-check --root . --base "$PR_BASE_SHA"
    --policy-ref "$PR_BASE_SHA" --json
```

Keeping the policy on the target branch prevents a candidate PR from editing
the policy to permit its own unrelated files. If a project is bootstrapping the
guard for the first time, merge the policy and CI step together, then require
the check on subsequent PRs. The Code Factory repository uses this same check
in its pull-request review workflow.

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
