# Code Factory LangGraph Proof Plugin

This cross-tool plugin gives Codex, Claude Code, and Deep Agents guidance for
using Code Factory as a local proof layer around a LangGraph test harness.

It ships two deliberately bounded surfaces:

- `langgraph-proof`, a skill for recording and comparing team-owned reference
  and resumed runs without overclaiming what the evidence proves.
- `code-factory-langgraph`, a local stdio MCP configuration exposing existing
  Code Factory facts, including read-only `factory.langgraph_assurance`.

The plugin does not install Python packages, invoke LangGraph, mutate a
checkpoint, replay an effect, repair code, or authorize a release. Install
`factoryline-code-factory>=0.40.0` in the environment that runs the local MCP
server before enabling it.

See [the installation and workflow guide](../../docs/LANGCHAIN_MARKETPLACE.md).
