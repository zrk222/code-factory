# Plan: langgraph-marketplace-plugin
Spec: specs/langgraph-marketplace-plugin.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Create matched Codex and Claude plugin manifests, a local stdio MCP config,
   a bounded proof skill, and a read-only GitHub proof starter.
2. Add a Code Factory marketplace index and public installation guide for
   Codex, Claude Code, and Deep Agents. State the package prerequisite and
   upstream marketplace review boundary explicitly.
3. Add static tests that reject missing manifests, version drift, MCP command
   drift, unsafe workflow permissions/triggers, or unsupported install docs.
4. Validate manifests, focused tests, strict SpecLine gates, ForgeLine
   architecture/reverse checks, and submit the portable plugin to the
   separately reviewed LangChain marketplace.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [ ] T1 | slice=plugins | files=<=4 | verify=`python C:\\Users\\rkatz\\.codex\\skills\\.system\\plugin-creator\\scripts\\validate_plugin.py plugins/code-factory-langgraph` | Create cross-tool manifests, proof skill, and read-only MCP configuration.
- [ ] T2 | slice=plugins | files=<=4 | verify=`python -m pytest -q tests/test_langchain_plugin.py` | Add the permission-minimal GitHub proof starter and static packaging-contract tests.
- [ ] T3 | slice=docs | files=<=4 | verify=`python -m pytest -q tests/test_langchain_plugin.py tests/test_ai_client_docs.py` | Add marketplace index, installation guide, and public LangGraph documentation link.
- [ ] T4 | slice=marketplace | files=<=4 | verify=`python -m pytest -q tests/test_langchain_plugin.py` | Submit the same portable plugin as a reviewed upstream LangChain marketplace contribution.
