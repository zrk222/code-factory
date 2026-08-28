# Spec: langgraph-marketplace-plugin
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Package the existing Code Factory LangGraph assurance surface as a portable
plugin for Codex, Claude Code, and Deep Agents, with a source-controlled
marketplace entry. The plugin must guide a coding agent to compare supplied
LangGraph receipts without turning the agent into a graph runner, repair agent,
or release authority.

### User roles
- LangGraph developer: wants an existing coding agent to help prepare and read
  a resume-parity proof without moving raw state into a new service.
- Reviewer: wants a pull-request proof starter that fails closed on a supplied
  divergence but does not receive merge authority.
- Marketplace maintainer: needs portable manifests with transparent Python
  prerequisite and no silent installation or credentials.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- The system shall write `code-factory-langgraph` into identical Codex and Claude Code manifests bound to Code Factory `0.44.0` and `factory mcp serve --root .`.
- When a supported coding agent loads the plugin, the system shall return a proof skill containing `LANGGRAPH_RESUME_PARITY_VERIFIED`, `LANGGRAPH_REPLAY_DIVERGENCE`, and `LANGGRAPH_INPUT_REJECTED` without production-resilience or savings claims.
- When a developer requests a local receipt comparison, the system shall emit a no-write CLI form and require explicit user approval before adding `--out`.
- When a pull request contains the declared sealed receipt paths, the system shall return the action verdict from `zrk222/code-factory@v0.44.0` with `contents: read`, exclude `pull_request_target`, and retain no write, merge, repair, graph, checkpoint, side-effect, deployment, publication, messaging, credential, or connector authority.
- If the Code Factory CLI is unavailable, the system shall return the `factoryline-code-factory-v043` prerequisite marker with the `factoryline-code-factory>=0.43.0` install instruction and shall not install it or alter client configuration itself.
- Where the Code Factory marketplace is used, the system shall return a repository-local `marketplace.json` entry and Codex, Claude Code, and Deep Agents install forms.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: coding agent requests a resume proof
  Given sealed workspace-relative reference and resumed LangGraph lineages
  When the user asks the coding agent to compare them
  Then the plugin guides a no-write `factory langgraph replay-verify` command
  And it does not invoke LangGraph, mutate a checkpoint, replay an effect, or authorize a repair

Scenario: pull request has a divergence
  Given the declared LangGraph receipt paths exist in a pull request
  When the included GitHub proof starter runs
  Then it runs Code Factory version `0.44.0` with read-only contents permission
  And a divergence fails the job without granting merge or repair authority

Scenario: plugin install has no hidden dependency action
  Given the plugin is installed but the factory CLI is absent
  When the coding agent prepares MCP setup
  Then it explains the explicit Python package prerequisite
  And it does not install a package or modify the coding-agent client configuration

Scenario: static plugin contract cannot be weakened
  Given the Code Factory LangGraph marketplace plugin contract
  When strict validator mutation runs
  Then both manifests retain `code-factory-langgraph` and version `0.44.0`
  And the skill retains `LANGGRAPH_RESUME_PARITY_VERIFIED`
  And the skill requires explicit approval before it adds `--out`
  And the GitHub starter retains `zrk222/code-factory@v0.44.0` and `contents: read`
  And the starter excludes `pull_request_target`
  And the proof skill retains `factoryline-code-factory-v043` and setup documentation retains `factoryline-code-factory>=0.43.0`
  And the marketplace index retains `marketplace.json`
```

## SHOULD — Technical/structural
- ADR references: `adr/factory-mcp-v1.md`; LangGraph remains the runtime and
  Code Factory remains a receipt-governed proof adapter.
- Data model: plugin packaging (`MCP` server name, manifests, a Markdown skill,
  and a static GitHub Action starter). No new runtime data or service is added.
- API contract: `factory mcp serve --root .`, read-only
  `factory.langgraph_assurance`, and `factory langgraph replay-verify`.

## SHOULD NOT — Implementation details
<!-- The plugin must not embed secrets, call a remote service, start LangGraph,
 mutate a checkpoint, replay effects, silently install dependencies, alter a
 client configuration, or authorize repair/release actions. -->

### Authorized bounded constants
- Static packaging reads use UTF-8. The numeral `8` in the encoding name is
  descriptive, not a runtime or product parameter.
- Static tests locate the repository root from `Path(__file__).parents[1]`.
  The parent index is a fixed repository-layout detail, not a user-controlled
  capability.
- The plugin smoke has one contract check, requires exit status `0`, and has a
  `30`-second local timeout. These values only bound deterministic local
  validation; they do not grant runtime authority or change the plugin API.
- Plan task metadata may use `files=<=4` as the SpecLine atomic-slice limit.
  It is planning metadata rather than a package behavior.

## Decision logic (factory candidates)
This feature has no HSF business-decision candidate. It is a static,
deterministic packaging contract validated by manifest, text-boundary, and
workflow-shape tests. Runtime verdicts remain owned by the existing LangGraph
Assurance Bridge.
