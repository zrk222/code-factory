# Diff-to-Proof Review

`factory change review` gives one deterministic answer to the question a
developer asks after a real diff: **what did this change affect, what evidence
is stale or missing, and what is the smallest defensible next review action?**

```powershell
factory change review --root . --base origin/main --json
factory change review --root . --changed factoryline/graph_ops.py --out-dir .factory/change-reviews
```

The command joins only existing local facts:

- Git changed paths, unless explicit `--changed` paths are supplied;
- exact Graph Ops proof-input impact and stale-proof state;
- requirement coverage facts, including missing coverage manifests;
- the existing risk-diff policy's **plan-only** rerun stages.

It returns JSON, deterministic Markdown, and a Mermaid map. With no `--out-dir`
it writes nothing. An explicit output directory writes only local review JSON,
Markdown, and Mermaid artifacts beneath that chosen directory.

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
