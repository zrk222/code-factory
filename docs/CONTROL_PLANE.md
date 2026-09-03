# Control Plane: evidence before authority

## Shared protocol values

Factoryline manifests deliberately remain plain JSON. The runtime now exposes
one small shared enum boundary for the cross-module values that change control
semantics: provenance origin and rule effect, autonomy, provider handoff
state, declared isolation, workflow role/capability, evidence tier, lifecycle
stage, repair consequence, and Mission Control state.

This is implementation hardening, not a new approval path:

- Existing manifests keep their exact string values and remain readable.
- New validators use the same canonical values across Oracle Firewall, Agent
  Bridge, Atomic proof adapter, lifecycle, operations, and repair packets.
- An unsupported value is rejected by the existing fail-closed schema
  validators; an enum never grants authority or proves a provider action.

Code Factory 0.46 adds one local, deterministic control model for humans and
connected agents. It is designed for teams that need to retain decision
authority while still giving agents enough exact context to work safely.

## The shared model

| Lane | What it binds | Who decides | What it never does |
| --- | --- | --- | --- |
| Oracle Firewall | Original request, approved obligations, negative cases, and thresholds | Named human / trusted source | Lets an agent rewrite the definition of done |
| Operations Control | Git base, branch, reproduction budget, change envelope, proof tier, architecture zones, and pinned local repo heads | Named human | Creates a worktree, dispatches an agent, or merges |
| Session Trace | Declared harness/session, stage, input/output hashes, sealed Oracle Contract, and predecessor receipt | Human reviews continuity | Proves provider identity or actual execution |
| Repair Loop | Exact `E_` issue, affected obligations, potential consequences, reproduction, candidate, positive and negative re-checks | Named human reviewer | Guesses repairs or self-approves one |
| Repository Coordination | Explicit dependency DAG and expected local Git heads | Human approves the actual work sequence | Pulls, pushes, checks out, merges, or rebases |
| Domain Ontology | Human-approved concepts, definitions, owners, invariants, and allowed relationships | Domain owner | Invents a vocabulary or treats terms as interchangeable |

## Human and agent protocol

Humans see the same local facts in Graph Ops Mission Control that a connected
agent can read through stdio MCP. The difference is authority: the agent may
read the sealed facts and prepare a separately reviewed proposal; it may not
alter intent, lower a threshold, add an exception, run a repair, approve,
merge, publish, deploy, or access credentials.

```text
Original intent -> sealed Oracle Contract -> operating envelope
     -> session trace -> repair packet -> named human decision
```

Unknown, invalid, stale, or drifted evidence fails closed. A green worker test
or an agent summary does not override any link in the chain.

## Local commands

```powershell
factory operations-control template --json
factory lifecycle template --json
factory repair-loop template --json
factory repo-coordinate template --json
factory ontology template --json
factory mission-control status --json
factory mcp serve
```

Templates contain no credentials and make no external calls. The `assess`,
`record`, and `plan` commands only write or inspect local evidence; none starts
an agent or changes a repository.
