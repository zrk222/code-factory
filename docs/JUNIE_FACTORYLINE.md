# FactoryLine taxonomy for Junie

FactoryLine gives Junie a project-local, progressive map of the proof system.
It is designed to stop a coding agent from treating every available command as
its default workflow.

## The route

1. **Orient.** Read the local status, next action, prior receipts, and IDE
   playbook. Unknowns remain unknown.
2. **Contract.** Bind human-owned intent, non-goals, forbidden behavior,
   negative cases, and scope before code changes.
3. **Review.** Map the proposed diff to the graph, proof delta, continuity,
   and human judgment route.
4. **Audit.** Use the relevant deterministic and independent challenge lanes
   for test truth, contradictions, workflow behavior, and runtime risk.
5. **Handoff.** Give Junie a sealed repair mission and independently evaluate
   its returned changed paths plus supplied analyzer and E2E evidence.
6. **Optional routes.** Enterprise, release, AppForge, SaaS, and revenue tools
   are available only when a task explicitly needs them.

The complete, versioned list is returned by the local read-only MCP tool
`factory.junie_taxonomy`; it includes every tool that the same MCP server
exposes.

## Proof-coupled change acknowledgement

The most useful additional JetBrains integration is not another agent switch:
it is a reviewable answer to *why is this change here, and what did the agent
actually check?* JetBrains already supplies a diff viewer, selective revert,
and grouped change review. FactoryLine adds an evidence route beside that
review: `source → obligation → forbidden behavior → gate → test → evidence →
decision`.

After Junie uses one or more `factory.*` tools, it calls the read-only
`factory.junie_contribution` MCP tool before its final handoff. The declaration
names the exact FactoryLine tools it says it used, the current taxonomy digest,
workspace-local changed paths and evidence paths, a short rationale for every
changed path, a plain-language benefit, and remaining unknowns. FactoryLine
validates the tool vocabulary, requires a rationale for every declared changed
path, and hashes each cited local file, then returns a visible `credit_line`
that Junie includes in its handoff.

That credit is intentionally narrow: it is a declared, evidence-bound
acknowledgement. It is **not** telemetry, an internal Junie score, proof of
Junie's private reasoning or MCP history, proof a test ran, or approval of the
change. The reviewer still reads the diff and decides whether the evidence
supports it.

## Project setup

From the project root, a human can install the secret-free project pack:

```text
factory junie install --root . --confirmation "INSTALL Junie FactoryLine Pack"
```

This creates only these files, unless an existing FactoryLine entry is already
identical:

- `.junie/AGENTS.md` — the progressive working contract for Junie.
- `.junie/mcp/mcp.json` — a local stdio `factory mcp serve --root <project>`
  configuration.

The installer refuses to overwrite a different team-owned guidance file or
MCP entry. It does not enable a server, start Junie, edit source, run tests,
approve, merge, publish, deploy, sign, use credentials, or contact JetBrains.

In JetBrains, the user must independently enable use of custom MCP servers for
Junie and confirm that the local `code-factory` server is available. Junie
then starts by calling `factory.junie_taxonomy`; for a repair, a human creates
a scoped FactoryLine packet before Junie calls `factory.agent_proof_mission`.

## The working contract

Junie must not widen scope, lower a threshold, remove a negative test, add an
exception, or reclassify a defect as expected behavior merely to make a result
green. When it cannot establish a required fact, it returns that fact as an
unknown for the human reviewer. Its final handoff contains changed paths, tests
run, evidence locations, failures, and remaining unknowns.

FactoryLine’s outputs remain evidence-navigation and review aids. They do not
make Junie autonomous, prove a provider action, or replace human approval.

## References

- [Junie in JetBrains IDEs](https://junie.jetbrains.com/docs/junie-ide-plugin.html)
- [Junie MCP configuration](https://junie.jetbrains.com/docs/junie-cli-mcp-configuration.html)
- [Junie project guidelines](https://junie.jetbrains.com/docs/guidelines-and-memory.html)
