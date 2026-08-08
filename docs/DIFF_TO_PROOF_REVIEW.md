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

## What it never does

Diff-to-Proof Review does not run tests or a replay plan. It does not modify
source, create a trace, merge, publish, deploy, sign, send messages, access
credentials, or grant connectors. A recommendation is not evidence that a
command ran; an unmatched changed path, stale proof, and missing coverage stay
visible until independently resolved.
