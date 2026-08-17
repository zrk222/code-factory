# Graph Portfolio and Run Admission

Graph Portfolio turns the existing local Graph Ops result into a deterministic
work proposal. Run Admission seals one selected external-run proposal against
the current workspace and requires the selected harness to re-check it before
it starts.

Neither feature runs a command, calls a model or network service, applies a
repair, approves work, or changes release authority.

## The practical workflow

```powershell
# Read the dependency shape that is already present.
factory graph portfolio --root . --json

# Create a reviewed Loop Passport first; its declared actions, paths, trigger,
# budget, and protected approvals bound the request below.
factory loop passport .factory/loops/dependency-audit.loop.json --root .

# Seal one short-lived request. It is a proposal, not an execution command.
factory admission prepare .factory/loop-passports/dependency-audit.passport.json .factory/admission-request.json --root . --json

# The selected, separately approved harness must run this immediately before it
# consumes the packet.
factory admission verify .factory/admissions/dependency-audit-run-1.admission.json --root . --json
```

An admission request uses `factory.run-admission.request.v1` and contains an
identifier, the exact Passport trigger, declared actions and workspace paths,
budget values no greater than the Passport budget, required named approvals,
and a `valid_until` RFC3339 timestamp. The deadline is at most 3,600 seconds
ahead and cannot exceed a required approval expiry.

## What the planner returns

- A stable, lexical workset with structural depth and slack.
- A structural critical path. When supplied duration observations cover every
  graph node and are positive, it also reports only the bound critical-path
  duration.
- Proposal-only safe parallel waves. A wave does not start work or authorize
  reuse.
- High-fan-out shared-proof candidates. They do not authorize proof reuse;
  [Proof Reuse](PROOF_REUSE.md) remains the exact independent gate.
- Explicit blocker chains. A blocked ancestor makes every reachable downstream
  node `BLOCK` instead of pretending it is safe to schedule.

No time, token, cost, or productivity savings are claimed here. Those values
remain null unless a separate, paired evidence system supports them.

## What a packet binds and re-checks

`factory admission prepare` atomically writes a local packet only after it
verifies the Loop Passport, Graph Ops completeness, paths, actions, budgets,
approvals, validity window, workspace fingerprint, and base graph hash. Its
authority object is false for execution, approval, repair, merge, publication,
deployment, signing, messaging, credential, and connector actions.

`factory admission verify` returns exactly one of:

| Verdict | Meaning | Required next step |
|---|---|---|
| `ADMISSION_READY` | Every local binding is still current. | The separately approved harness may apply its own runtime controls. |
| `ADMISSION_STALE` | Workspace or graph content changed. | Create and review a new packet. |
| `ADMISSION_PACKET_BLOCKED` | Packet, Passport, request, approval, or validity binding failed. | Resolve the named cause; do not run it. |

The packet is deliberately not a sandbox, credential, identity, egress, or
tool-execution policy. The chosen harness must enforce those controls itself.

## Graph Ops surface

Open `factory studio --root .`, then **Graph Ops**, to see the Portfolio Flight
Plan. It displays critical-path nodes, safe waves, shared candidates, blocker
chains, timing state, and projected sealed packets. Its **Run selected wave**
and **Authorize external harness** controls are intentionally disabled. They
make the boundary visible rather than simulating authority Code Factory does
not possess.

For the broader local evidence model, see [Unified Graph Ops](GRAPH_OPS.md),
[Loop Passport](LOOP_PASSPORT.md), and [Factory Continuity](FACTORY_CONTINUITY.md).
