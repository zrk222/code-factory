# Earned Autonomy and Combine

Code Factory keeps two distinct proof questions separate:

1. **Can the proposed change survive its required checks?** Use existing
   product proof gates and the Gauntlet.
2. **What authority may this declared agent request on this repository today?**
   Use an Agent License derived from governed run evidence.

An Agent License is a local, expiry-bound governance artifact. It is not an
identity-provider credential, a quality score, a performance benchmark, or an
execution permission.

## Agent License

Each run must first pass the existing `factory admission` boundary. A separate
verifier subject records an immutable `factory.agent-run.v1` event with
hash-bound result and verification receipts. The verifier subject must differ
from the declared agent subject.

```text
admitted request -> independent verifier receipt -> immutable governed event
                 -> current license derivation -> narrower admission cap
```

The V1 policy is explicit and local:

- 3 clean current governed events reach **supervised**;
- 20 clean current events plus 15 independent verifications and a stable common
  workspace scope can reach **autonomous**;
- evidence expires after 30 days without a fresh governed event; and
- a `hollow_test`, `hollow_validator`, or `scope_escape` event immediately
  demotes the affected agent to **human controlled** until 5 fresh clean runs.

Those numbers are configurable product policy values, not an empirical claim
about model safety or a vendor ranking. They should be reviewed by the team
that owns the repository.

```sh
# Record only an already-admitted and independently verified run.
factory license record .factory/events/agent-run.json --root . --json

# Derive or write the current local license from current evidence.
factory license status --agent .factory/agent.json --root . --json
factory license issue --agent .factory/agent.json --root . --json
factory license verify .factory/agent-licenses/licenses/<identity>.json --json
```

A request with a declared agent identity is checked during `factory admission
prepare`. If its Loop Passport requests an autonomy tier beyond the current
license, or an autonomous request exceeds the earned common scope, admission
fails closed with `E_LICENSE_EXCEEDED`.

No command above starts a model, creates an identity, runs a repair, approves a
change, merges code, publishes a package, deploys a service, signs by default,
or accesses credentials. Optional DSSE sealing binds an already valid license
to the existing Receipt v2 pathway; it does not make the underlying declared
identity externally authenticated.

## Combine

`factory combine` compares completed **governed** events on one human-written,
sealed task. It does not run arbitrary prompts or invoke agent executables.
The external harness owns process execution; Combine keeps comparison
deterministic and offline-verifiable afterwards.

```sh
factory combine task .factory/tasks/approval-tracker.json --root . --json
factory combine score .factory/combines/tasks/approval-tracker.json --root . --json
factory combine verify .factory/combines/scoreboards/approval-tracker.json --json
```

The sealed task stores the task description hash, not its body. Each declared
candidate contributes exactly one current governed event. Ranking is only:

1. passing result before non-passing result;
2. fewer severe failure classes;
3. fewer total failure classes; then
4. the declared identity hash as a deterministic tie breaker.

Elapsed time, token use, cost, and unmeasured quality remain explicitly
unobserved. A Combine scoreboard is not a leaderboard, benchmark, purchasing
recommendation, or proof that one model is superior outside the sealed task.

## Visual and MCP supervision

Graph Ops projects the tier, expiry, current evidence counts, automatic
incidents, and verified Combine scoreboards in a read-only supervision panel.
The local MCP server exports matching `factory.agent_license_status` and
`factory.combine_status` tools for assistants that can inspect facts but should
not gain mutation authority.
