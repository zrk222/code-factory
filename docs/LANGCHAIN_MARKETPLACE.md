# Code Factory for LangGraph coding agents

**Run LangGraph your way. Prove the resume path before review.**

Code Factory v0.40.1 adds a local, deterministic assurance layer for a
LangGraph test harness. It compares a sealed reference lineage with a
separately captured resumed lineage, returns parity only for matching supplied
evidence, and produces a hash-only incident capsule when they diverge.

It does not replace LangGraph, LangSmith, or your checkpointer. It does not
invoke a graph, expose raw state, replay effects, repair code, approve a pull
request, or claim production resilience or savings.

## Install the marketplace plugin

Install the Python package into the environment that will host the local MCP
server:

```bash
 python -m pip install -U "factoryline-code-factory>=0.41.0"
factory mcp status --root .
```

Then add the Code Factory marketplace and install the plugin.

### OpenAI Codex

```bash
codex plugin marketplace add zrk222/code-factory
codex plugin add code-factory-langgraph@code-factory
```

### Claude Code

```bash
/plugin marketplace add zrk222/code-factory
/plugin install code-factory-langgraph@code-factory
```

### Deep Agents Code

```bash
dcode plugin marketplace add zrk222/code-factory
dcode plugin install code-factory-langgraph@code-factory
```

Restart the coding agent after installation. The plugin starts a local stdio
MCP process rooted at the current workspace. Approve that local MCP server in
your client if the client prompts you.

## Use the proof surface

Have your team-owned harness record a reference run and a separately resumed
run using `LangGraphTransitionRecorder`, then seal the two lineages. Compare
them without writing a new receipt:

```bash
factory langgraph replay-verify \
  --root . \
  --reference .factory/langgraph/reference.json \
  --resumed .factory/langgraph/resumed.json \
  --json
```

Use `--out .factory/langgraph/assurance.json` only when a user has approved a
local assurance receipt. A GitHub Action starter is included at
`plugins/code-factory-langgraph/assets/github-actions/langgraph-proof.yml`.
It has read-only contents permission and makes a failing divergence visible in
the job; it does not make merge decisions.

## Official LangChain marketplace submission

This repository now provides its own marketplace entry and a portable plugin.
The LangChain Plugins marketplace has a separate upstream-review process. A
submitted contribution is not an endorsement or a completed listing; use the
Code Factory marketplace above while that review is pending.

## Boundaries

- The MCP tool `factory.langgraph_assurance` only reads existing,
  workspace-relative receipts.
- It cannot invoke a graph, mutate checkpoints, replay side effects, write
  receipts, approve repairs, merge, deploy, publish, message, or access
  credentials.
- `LANGGRAPH_RESUME_PARITY_VERIFIED` applies only to supplied sealed lineages.
  It does not prove production resilience, complete instrumentation, external
  idempotency, quality, time, token, cost, or productivity savings.

For the recorder API and exact evidence model, read the
[LangGraph Assurance Bridge](LANGGRAPH_ASSURANCE.md).
