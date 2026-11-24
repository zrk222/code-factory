# GitHub Proof Review

## Find the next pull-request blocker

```powershell
factory github pr-readiness 42 --root . --json
factory github pr-readiness 42 --root . --head-sha <expected-sha> --require-clear
```

The command uses the connected GitHub CLI and the checkout's `origin`. A single
read retrieves the PR state, base conflicts or lag, unresolved review threads,
CI check rollup, and review decision for the current head. The terminal view
leads with the first blocker. JSON includes the SHA, ordered blockers,
unresolved thread IDs and locations, and check states. When supplied, the
expected SHA must match both the PR and the commit that owns the check rollup.

Without `--require-clear`, a successful read exits 0. With it, blocked or
incomplete evidence exits 3. Invalid requests, unavailable provider evidence,
and head mismatches exit 2. The snapshot reads up to 100 threads and 100 check
contexts. Pagination, missing checks, and unknown mergeability prevent a clear
result. GitHub names and paths are untrusted data.

`NO_OBSERVED_BLOCKERS` is an advisory snapshot. Use your repository's merge
policy for the actual decision. This workflow performs no remote writes and
does not fetch review text. Its blocker ordering is inspired by the
[Pstack PR triage playbook](https://github.com/cursor/plugins/blob/ca782ed8b3c2c521cead8e1720d55c3a5dbf2347/pstack/skills/poteto-mode/playbooks/babysit.md).

## Compile local proof for review

`factory github proof-review` turns the existing local Diff-to-Proof Review
into a compact, evidence-bound GitHub pull-request surface. It answers a
narrow question: **what changed, what declared evidence is missing or stale,
and what fact-derived action should a reviewer take next?**

```powershell
factory github proof-review `
  --root . `
  --base origin/main `
  --head-sha abcdefabcdefabcdefabcdefabcdefabcdefabcd `
  --changed factoryline/change_review.py `
  --json
```

The command is local and has no GitHub credential or network dependency. It
first recompiles the current Diff-to-Proof Review, recomputes its canonical
SHA-256, and rejects altered source facts. A valid output contains:

- the exact pull-request head SHA and source review SHA;
- every changed path in exactly one documented cohort;
- the existing findings, unproven claims, Mermaid map, and fact-derived next
  action without an AI summary replacing them;
- one completed **`FactoryLine / Proof Review`** Check request with a neutral
  conclusion; and
- one stable Markdown walkthrough marked `<!-- factoryline-proof-review -->`.

With `--out-dir`, it writes only a JSON payload and Markdown walkthrough below
that explicitly selected directory. Without it, the command writes nothing.

### Path-cohort table

The cohort label comes from this fixed table; every changed path appears once,
or falls into `other`:

| Path prefix | Cohort |
| --- | --- |
| `specs/`, `requirements/` | `contracts` |
| `tests/`, `test/` | `tests` |
| `.github/`, `deploy/`, `infra/` | `delivery` |
| `docs/` | `docs` |
| `factoryline/`, `src/`, `lib/`, `app/`, `services/`, `editors/`, `packages/`, `scripts/` | `implementation` |
| any other workspace-relative path | `other` |

## Run it with CodeRabbit

CodeRabbit and Code Factory are complementary, not interchangeable:

| Review need | CodeRabbit | Code Factory |
| --- | --- | --- |
| AI-suggested code concerns and fixes | Its review surface | Does not imitate or ingest them |
| Deterministic local proof gaps | Can be discussed in review | Diff-to-Proof Review and receipts are the source of truth |
| PR walkthrough | AI-authored review walkthrough | Hash-bound changed scope, cohorts, findings, and next action |
| Merge decision | Team policy and reviewer judgment | Never approves, merges, or claims readiness |

When both are enabled, developers see CodeRabbit feedback and a FactoryLine
Proof Review Check on the same pull request. The latter does **not** call a
CodeRabbit API, need a CodeRabbit account, copy AI comments into receipts, or
treat AI output as verification evidence. A team can use the FactoryLine
workflow on its own, with CodeRabbit, or with another review tool.

CodeRabbit documents its own [IDE and CLI review surface](https://docs.coderabbit.ai/overview/ide-cli-review),
[pull-request walkthroughs](https://docs.coderabbit.ai/pr-reviews/walkthroughs),
and [pre-merge checks](https://docs.coderabbit.ai/pr-reviews/pre-merge-checks).
Those are external product capabilities; this integration only relies on both
systems being able to comment or check the same GitHub pull request.

## Enable the supervised delivery adapter

Copy [`.github/workflows/factory-pr-proof-review.yml`](../.github/workflows/factory-pr-proof-review.yml)
into the repository where your team wants this review surface. On a same-repository
pull request it:

1. checks out the exact head SHA with persisted credentials disabled;
2. compiles the local payload from the exact base-to-head path list;
3. creates or updates one marker comment; and
4. creates one neutral GitHub Check tied to the same head SHA.

The workflow uses only `contents: read`, `pull-requests: write`, and
`checks: write`. It ignores fork pull requests rather than exposing a
write-capable token to untrusted fork code. It does not use `pull_request_target`,
write source, run a repair, approve, merge, close, label, assign, publish,
deploy, access a provider credential, or invoke a model.

The Check is deliberately `neutral`: its facts help a human and the repository's
existing policy decide what happens next. It is not an assertion that the diff
is correct, production-ready, or safe to merge.

## LangGraph resume Proof Card

For a repository that records a normal and a separately resumed LangGraph test
run, add the free [`Code Factory LangGraph Proof Gate`](../action.yml) to a
workflow. It writes a `VERIFIED` or `REVIEW_REQUIRED` proof card and Mermaid
map to the job summary without invoking the graph itself. A divergence exits
non-zero after creating the requested receipt; a team, not this action, decides
whether that check is required for a merge. See [LangGraph Assurance](LANGGRAPH_ASSURANCE.md)
for the recorder contract and safe incident capsule.

## Free, shareable review artifact

The Markdown walkthrough is designed to be useful in a PR even when a reviewer
does not have FactoryLine installed. It provides an inspectable scope, an exact
review digest, and explicit unknowns without a dashboard login. If it helps a
team see a hollow test or stale proof, they may link the generated packet in
their own review discussion. Code Factory does not post, solicit reviews, or
contact anyone on a user's behalf.

For the local source facts, see [Diff-to-Proof Review](DIFF_TO_PROOF_REVIEW.md).
For larger independent evidence checks, see [Verifier Plane](VERIFIER_PLANE.md).
