# FactoryLine compatibility and handoff guide

FactoryLine is most valuable after an AI builder proposes or creates work and
before a person calls that work complete. It does not need to replace the
builder, orchestrator, reviewer, IDE, or CI system. It gives those systems a
shared local evidence contract: declared intent, exact scope, independent
validators, receipts, proof gaps, and a human-owned next decision.

## Choose the connection by job

| If your primary tool is… | Let it own… | Let FactoryLine own… | Recommended handoff |
| --- | --- | --- | --- |
| Blitzy | Codebase ingestion, Technical Specification, Agent Action Plan, generation, runtime validation, and PR creation | Approved-plan alignment, exact diff scope, hollow-test challenges, and commit-bound proof status | Export or retain the reviewed plan in the repository; run `factory plan verify`, `factory change review`, and GitHub Proof Review on the resulting PR |
| CodeRabbit | AI review, comments, summaries, and remediation suggestions | Deterministic local evidence, Proof Debt, and the neutral FactoryLine GitHub Check | Enable both on the same PR; keep CodeRabbit output advisory and FactoryLine receipts independent |
| Mastra | Agent logic, TypeScript tools, memory, workflow execution, and MCP client lifecycle | Read-only proof context plus independent post-run diff and validator evidence | Connect Mastra to `factory mcp serve` only when the local stdio contract fits; otherwise use CLI receipts and `factory wrap` around the approved harness |
| LangGraph | Runtime graph, checkpoint persistence, streaming, and application-owned effects | Reference-versus-resume parity, duplicate-effect and parallel-write checks, incident capsules, and receipt authority | Instrument the team-owned harness with `LangGraphTransitionRecorder`, seal both runs, then run `factory langgraph replay-verify` or the included GitHub Action |
| Codex / Claude Code / Deep Agents | Repository reasoning and implementation | Admission, scoped wrapping, independent validators, and governed-run evidence | Use `factory admission prepare`, `factory wrap`, the read-only MCP server, or the included LangGraph plugin as the task requires |
| Cursor / OpenCode | Interactive coding and MCP tool use | Bounded local receipt, verifier, PRD, memory, and Graph Ops facts | Add the documented local stdio MCP configuration and keep all mutation or publication outside the MCP server |
| DeepSeek Harness | Model and tool lifecycle | Local read-only evidence context | Load the opt-in Cordis overlay; treat upstream developer-preview behavior as a separate risk |

## Practical patterns

### Autonomous builder to governed pull request

Use this for Blitzy or another large-change generator:

1. A person reviews the builder’s plan and stores the approved scope.
2. The builder creates the change and pull request.
3. `factory plan verify` compares the exact diff with the approved plan.
4. `factory change review` identifies proof gaps and one next action.
5. Declared validators and negative cases run through the appropriate FactoryLine gate.
6. GitHub Proof Review publishes one neutral, commit-bound Check.
7. CodeRabbit or another reviewer may discuss the diff and Check; a person still decides whether to merge.

### Agent framework to independent proof

Use this for Mastra, LangGraph, or another agent runtime:

1. The framework owns execution, state, memory, and tool calls.
2. FactoryLine consumes only bounded, declared artifacts or read-only MCP facts.
3. The normal and failure/resume paths produce independently inspectable evidence.
4. FactoryLine verifies the supplied lineage, diff, tests, or receipts without treating the framework’s own success message as proof.
5. Graph Ops shows the evidence state and next supported action; it does not execute the agent.

### IDE assistant to local review handoff

Use this for Codex, Claude Code, Cursor, OpenCode, or a JetBrains AI workflow:

1. Scope the requested work and explicit external-effects boundary.
2. Let the assistant implement inside that scope.
3. Run First Proof, Change Review, Plan-to-Proof, or Gauntlet as appropriate.
4. Save the local handoff packet and inspect it in Factory Studio, Graph Ops, VS Code, or the JetBrains plugin.
5. Keep credentials, approval, merge, deployment, and publication in the user-controlled system.

## Status language

- **Included / native** means the repository contains the adapter, command,
  action, plugin, tests, or setup guide.
- **Documented interoperability** means the handoff is explicitly documented
  and uses a stable boundary such as GitHub Checks.
- **Protocol-level fit** means the products share a compatible protocol, such
  as MCP, but this repository does not claim a dedicated vendor adapter or a
  completed cross-product certification.
- **Workflow fit** means repository artifacts and CI can connect the products;
  it is not a direct integration or partnership claim.

External product capabilities can change. Verify their current documentation
and your own account configuration before adopting a production workflow.

Official capability references used for this guide:

- [Blitzy introduction](https://docs.blitzy.com/introduction)
- [CodeRabbit GitHub Checks](https://docs.coderabbit.ai/tools/github-checks)
- [Mastra MCP guide](https://mastra.ai/docs/agents/mcp-guide)
- [LangGraph documentation](https://langchain-ai.github.io/langgraph/index.html)
