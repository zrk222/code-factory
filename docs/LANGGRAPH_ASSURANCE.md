# LangGraph Assurance Bridge

**Run LangGraph. Prove its resume path.**

LangGraph provides durable execution primitives. Code Factory adds an
independent, local proof surface around a team-owned test harness: it compares
the recorded semantic transitions from a reference run and a separately
captured resumed run, without importing LangGraph, invoking a graph, mutating a
checkpoint, or replaying an external effect.

The bridge is useful when a graph appears to work normally but a resume,
parallel branch, or idempotent side effect needs evidence before a reviewer
accepts it.

## What it verifies

`factory langgraph replay-verify` accepts two sealed
`factory.graph-lineage.v1` receipts for the same graph. It returns one of two
deterministic outcomes:

| Marker | Meaning |
| --- | --- |
| `LANGGRAPH_RESUME_PARITY_VERIFIED` | The supplied, sealed transitions match and neither lineage has a deterministic anomaly. |
| `LANGGRAPH_REPLAY_DIVERGENCE` | The supplied transitions differ, or the bridge found a duplicate completed effect, stale read/write, or unsafe parallel write. |

On divergence it includes `LANGGRAPH_INCIDENT_CAPSULE`: a Mermaid map, receipt
hashes, first divergent node, state-key identifiers, anomaly facts, and the
smallest read-only recovery cone. It retains no raw state values, prompt text,
or source secrets. Teams may choose to attach that capsule to a pull request or
an upstream issue; Code Factory never posts it or contacts anyone.

## Record transitions in your own harness

The recorder is intentionally a small adapter. Your test controls how it runs
LangGraph, including how it creates the reference and resumed attempts.

```python
from pathlib import Path
from factoryline.langgraph_assurance import LangGraphTransitionRecorder

root = Path(".")
recorder = LangGraphTransitionRecorder("support-agent", "resume-attempt")

# Your harness runs a node and supplies only before/after state to the recorder.
recorder.record_transition(
    "classify",
    superstep=1,
    checkpoint_id="checkpoint-1",
    before_state={"request_id": "request-42"},
    after_state={"request_id": "request-42", "route": "triage"},
    decision={"route": "triage", "reason": "route selected"},
)
recorder.seal(root, ".factory/langgraph/resumed.json")
```

The recorder stores SHA-256 digests of supplied state values, side-effect
identifiers, and decision text. Use stable node, checkpoint, and state-key
identifiers; do not place secrets in identifier names.

Capture a normal reference run and a separately forced-resume run in the same
way, then compare them:

```powershell
factory langgraph replay-verify `
  --root . `
  --reference .factory/langgraph/reference.json `
  --resumed .factory/langgraph/resumed.json `
  --out .factory/langgraph/assurance.json `
  --json
```

The command exits `0` only for `VERIFIED`; a divergence exits `1` after writing
the requested receipt. Invalid state, a malformed lineage, mismatched graph
identifier, absolute path, or path escape is rejected before an output is
written.

## Free GitHub Action

Use the repository action to make the same result visible in a pull-request job
summary. It accepts already-recorded receipts; it does not run an agent graph.

```yaml
name: LangGraph proof
on: [pull_request]
permissions:
  contents: read
jobs:
  replay-parity:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: zrk222/code-factory@v0.44.1
        with:
          reference: .factory/langgraph/reference.json
          resumed: .factory/langgraph/resumed.json
          out: .factory/langgraph/assurance.json
```

The action writes `verdict`, `marker`, and `receipt` outputs, plus a Mermaid
Proof Card in the job summary. A divergence intentionally fails the action so a
team can decide whether to make that check required. It neither comments on a
pull request nor requests token permissions for merge, repair, deployment,
publication, or credentials. Pair it with the existing
[GitHub Proof Review](GITHUB_PROOF_REVIEW.md) when a team also wants one
advisory, commit-bound changed-scope walkthrough.

## MCP for an assistant you choose

An MCP-capable coding assistant can read a supplied comparison, but cannot
create a receipt or trigger a graph through this tool:

```json
{
  "name": "factory.langgraph_assurance",
  "arguments": {
    "reference": ".factory/langgraph/reference.json",
    "resumed": ".factory/langgraph/resumed.json"
  }
}
```

The result is marked `LANGGRAPH_MCP_READ_ONLY` and explicitly has false graph
invocation, checkpoint mutation, side-effect replay, approval, deployment,
publication, credential, and connector authority.

## What this does not prove

- It does not run LangGraph or verify that a harness captured every transition.
- It does not establish production resilience, external-system idempotency, or
  correctness outside the supplied lineages.
- It does not repair, approve, merge, deploy, publish, or message anyone.
- It does not report time, token, cost, quality, or productivity savings. Those
  require a separately defined, paired measurement.

## Coding-agent plugin

The [Code Factory LangGraph plugin](LANGCHAIN_MARKETPLACE.md) packages the
same bounded workflow for Codex, Claude Code, and Deep Agents. It adds
proof-oriented instructions and a local, read-only MCP configuration; it does
not give the coding agent graph execution, checkpoint mutation, repair, or
release authority.

## Free core; future team service

The recorder, sealed receipt format, CLI, MCP tool, and GitHub Action are open
and local-first. A future optional team service can add authenticated GitHub-App
delivery, organization policy administration, retention, SSO/RBAC, and a
multi-repository evidence ledger. Those service features are not active,
required, or implied by a local parity receipt.
