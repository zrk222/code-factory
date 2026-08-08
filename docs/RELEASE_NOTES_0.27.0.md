# Code Factory 0.27.0

## Independent verification, made inspectable

0.27.0 adds the local **Verifier Plane**. It creates and validates
hash-bound evidence contracts for a mission candidate:

- a mission and candidate-tree digest;
- an immutable verifier bundle outside the candidate tree;
- declared independent worker and verifier identities;
- exact worker, toolchain, and evidence digests;
- deterministic check results; and
- hard ceilings for attempts, wall time, tokens, and cost.

The verifier rejects self-verification, stale inputs, verifier-bundle drift,
candidate-path escape, evidence drift, budget excess, and a passing result with
a failed declared check. `factory verifier progress` detects an exact repeated
failure without measured improvement and sends the decision to the named owner.

Graph Ops now displays verifier sessions as a separate read-only lane. A
session begins `runtime-unattested`: Code Factory will not pretend that a local
receipt proves a container, Kubernetes namespace, host, egress policy, or
credential boundary was actually enforced.

## Commands

```powershell
factory verifier session .factory\missions\<mission>\mission.json .\candidate `
  --bundle .\verification\checks.json --owner engineering-owner --root .
factory verifier verify .factory\verifier-sessions\<session>.session.json `
  .\worker-result.json .\verifier-result.json --root . --json
factory verifier progress .\attempts.json --json
```

## Boundary

This version supplies and validates the contract; it does not execute a worker,
call an LLM, inject a secret, run a container, or authorize release actions. An
external supervised runner must enforce runtime isolation and attach its own
attestation as evidence. LLM rubrics may be recorded as supplementary evidence
but cannot override a compiler, schema, policy, or test gate.

## Channels

- GitHub release: source, Python artifacts, VSIX, and JetBrains ZIP attach only
  after the release workflow validates them.
- PyPI: uses Trusted Publishing from the verified GitHub release workflow.
- Hugging Face: publishes the updated static surface from `main` after its
  workflow validates Space metadata.
- Open VSX and JetBrains Marketplace: remain separately protected by scoped
  publisher tokens and their respective review/pending-update gates.
