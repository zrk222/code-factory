# Oracle Firewall

Oracle Firewall prevents an AI worker from becoming the author, judge, and
reviser of its own definition of done. It is a local evidence layer above
tests, gates, and autonomous admission. It does not call a model, run code,
alter a candidate, approve a change, or authorize a release.

## The problem it solves

An apparently green workflow can still be wrong when the same agent that wrote
the feature also chooses the threshold, removes the negative case, adds the
exception, or redefines a defect as expected behavior. A green result is not
proof that the oracle remained intact.

Oracle Firewall makes the oracle itself reviewable:

```text
original source -> approved obligation -> forbidden behavior -> gate -> test -> evidence -> decision
```

Every rule has one origin: `human_confirmed`, `trusted_source`,
`observed_production`, or `agent_proposed`. Only a human-confirmed or
trusted-source rule may block or release work. Agent-proposed and observed
production inputs remain advisory unless a separate human-approved successor
contract promotes them.

## Start a complete local workspace

The initializer captures the exact original intent bytes, creates deliberately
incomplete contract and challenge templates, and writes the next human steps.
It never guesses approvals or creates a green release state.

```powershell
factory oracle init `
  --root . `
  --source-path .\product-intent.md `
  --agent "codex" `
  --contract-id checkout-safety-v1 `
  --scope src\checkout.py `
  --out-dir .factory\oracles\checkout-safety
```

For an AppForge candidate, add `--appforge`. The resulting authority template
binds the candidate, named human reviewer, policy sources, and sealed Oracle
contract. It does not submit to App Store Connect or claim Apple approval.

## Seal, challenge, and supervise

1. A product owner completes and approves the template, including intended
   outcomes, forbidden outcomes, negative cases, sources, and gate values.
2. `factory oracle seal` verifies source hashes and writes a signed local
   contract. Candidate code cannot change that digest.
3. `factory oracle challenge compile` creates independent,
   implementation-targeted boundary and counterfactual cases. The verifier
   context cannot edit the code or contract.
4. `factory oracle challenge verify` accepts an externally supplied result
   only when every planned implementation mutation was killed.
5. `factory oracle diff` treats a deleted negative test, relaxed threshold,
   new exception, or provenance downgrade as `E_ORACLE_WEAKENING` and blocks
   promotion pending review.

```powershell
factory oracle status --root . --json
factory graph ops --root . --json
```

Graph Ops and FactoryLine's **Oracle** tab are read-only supervision views.
They make the evidence chain and `E_ORACLE_WEAKENING` visible; neither can
approve changed intent, repair code, or release work.

## Autonomy boundary

Autonomous admission requires a current, hash-matching sealed contract with no
unresolved advisory proposal. A scope, intent, threshold, or exception change
pauses that run. Recording an Oracle weakening incident demotes the declared
agent to supervised/human-controlled operation through the existing Agent
License evidence model.

This is a local provenance and evidence check. It does not prove real-world
identity, authenticate an agent vendor, prove an implementation correct, or
guarantee a release outcome.
