# Code Factory 0.36.0

## Graph Portfolio and Run Admission

Code Factory 0.36.0 adds a governed way to turn the evidence already present
in Graph Ops into a reviewable delivery proposal without creating an autonomous
runner.

- `factory graph portfolio --root . --json` returns a deterministic structural
  critical path, slack, lexical workset, proposal-only safe parallel waves,
  shared-proof candidates, and blocker chains. A blocker propagates visibly to
  downstream work. Duration is reported only for a complete supplied set of
  positive observations; time, token, cost, and productivity savings remain
  unavailable here.
- `factory admission prepare` seals a local Run Admission Packet to the current
  workspace fingerprint, base Graph Ops digest, verified Loop Passport,
  declared actions and paths, bounded budget, required named approvals, and a
  validity deadline of at most 3,600 seconds.
- `factory admission verify` reports ready, stale, or blocked immediately
  before an external harness consumes a packet. A changed workspace or graph
  yields `ADMISSION_STALE`; invalid, tampered, expired, or unauthorized inputs
  yield `ADMISSION_PACKET_BLOCKED`.
- Graph Ops adds a responsive **Portfolio Flight Plan** that exposes these
  facts, packet posture, and visibly disabled external-harness controls.

## Authority boundary

This release does not execute work, run a selected harness, apply a repair,
authorize an external runner, reuse a proof, merge, publish, deploy, sign,
send a message, access credentials, grant a connector, or infer outcome or
productivity claims. The selected harness still owns its actual identity,
sandbox, network, credential, and tool policies.

## Install

```powershell
pip install factoryline-code-factory==0.36.0
factory graph portfolio --root . --json
```

See [Graph Portfolio and Run Admission](GRAPH_PORTFOLIO_ADMISSION.md) for the
complete local workflow and contract.
