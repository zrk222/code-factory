# Proof Continuity Ledger

The Proof Continuity Ledger is Code Factory's repository-level senior-engineering
audit receipt. It is not an AppForge feature and it does not make an agent's
green build authoritative. AppForge is simply one optional evidence lane beside
tests, independent challenges, CI, runtime observations, and release evidence.

It seals one immutable chain for one exact repository revision:

```text
source -> obligation -> forbidden behavior -> gate -> test -> evidence -> decision
```

Only Oracle rules with `human_confirmed` or `trusted_source` provenance and a
`blocking` or `release` effect can enter that chain. Agent-proposed and
observed-production rules remain outside the release chain until a named human
or trusted source promotes them through the Oracle Firewall.

## What it does

`factory proof-continuity seal` reads a current sealed Oracle Contract and a
fixed-shape local input. It binds:

- repository, exact Git-like revision, and approved scope;
- the Oracle's original-intent handoff and contract digest;
- every critical requirement, forbidden behavior, gate, and test;
- hash-valid evidence references, optionally including AppForge, CI, challenge,
  runtime, device, storefront, capture, or release receipts;
- the named reviewer and rationale; and
- a human-controlled or supervised autonomy posture.

`factory proof-continuity observe` attaches later local evidence to one sealed
obligation. A `contradicted` observation emits `E_PROOF_CONTINUITY_REOPENED`,
opens a local incident capsule, and changes the recommended autonomy mode to
`supervised`. An `inconclusive` observation requires review. Neither outcome
changes code, runs a test, revokes a real credential, contacts a provider, or
approves/rejects a release.

## Minimal workflow

1. Capture the original request and seal an Oracle Contract.
2. Collect independent, hash-valid evidence receipts for the exact revision.
3. Create a `factory.proof-continuity-contract-input.v1` with the complete
   source-to-evidence chain.
4. Seal it locally:

   ```powershell
   py -3 -m factoryline.cli proof-continuity seal --root . `
     --input audit-input.json `
     --out .factory/proof-continuity/contracts/<audit>.json --json
   ```

5. Review it in Graph Ops or through the read-only MCP tool
   `factory.proof_continuity_status`.
6. When later evidence changes the picture, create a bounded observation input
   and record it. Treat a reopened chain as a named human-review event, not as
   permission for an agent to rewrite the gate.

## Boundary

The ledger is Windows-operable because it reads and writes bounded local JSON
only. It provides audit integrity, not execution proof: no tests, simulators,
devices, providers, credentials, releases, deployment, or approval actions run
through this command. A receipt reports the evidence that was bound; it does
not claim that the evidence source was truthful or that an external system
accepted work.
