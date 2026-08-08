# Verifier Plane

The Verifier Plane makes an independent verification boundary inspectable and
machine-checkable. It is intentionally an **evidence contract**, not a hidden
agent runtime: Code Factory binds the mission, candidate tree, immutable
verifier bundle, worker result, verifier result, deterministic checks, and
budget declarations without executing a worker, starting a container, calling
a model, or accessing a credential.

This solves the most important first problem in agentic delivery: a worker must
not certify its own work. It does not claim to solve host isolation by itself.
An external supervised runner remains responsible for actually enforcing its
filesystem, process, network, secret, and egress boundaries.

## What is enforced locally

`factory verifier session` creates a hash-bound local session from:

- one existing `factory.mission.v1` receipt;
- a candidate directory the worker may change;
- one or more verifier-bundle files outside that candidate directory; and
- hard declared ceilings for attempts, wall time, tokens, and cost.

`factory verifier verify` validates supplied worker and verifier receipts. It
rejects a result when the worker and verifier identities match, the verifier is
not declared fresh and isolated, the candidate tree or verifier bundle has
drifted, evidence bytes have drifted, a declared write escapes the candidate
tree, a budget is exceeded, or a `passed` verdict contains a failed deterministic
check. A valid receipt has no merge, publishing, deployment, or credential
authority.

```powershell
# First create a normal Product Mission, then bind an independent verifier.
factory verifier session .factory\missions\<mission>\mission.json .\candidate `
  --bundle .\verification\checks.json --owner engineering-owner --root .

# An external, supervised runner writes the two receipts. Code Factory only
# validates their byte bindings and declared boundaries.
factory verifier verify .factory\verifier-sessions\<session>.session.json `
  .\worker-result.json .\verifier-result.json --root . --json
```

## Deterministic no-progress halt

The optional progress receipt detects a repeated **exact** failure signature
without a measured improvement in passed checks, failed checks, or covered
criteria. It requests owner review; it does not use an LLM to decide whether an
attempt made progress.

```powershell
factory verifier progress .\attempts.json --json
```

When the result is `stalled`, the next action is `owner_review`, not an
automatic retry. This keeps a loop from spending its way through the same
failure.

## Rubrics and LLM graders

An LLM rubric may be attached as additional verifier evidence, but it is never
a terminal authority. Compilers, schemas, policy checks, and non-hollow tests
remain the gate conditions. A rubric cannot turn a failing deterministic check
into `passed`, grant a retry past the hard budget, or authorize merge, release,
deployment, credentials, or external messaging.

## Project context and architectural invariants

The plane deliberately verifies against project-owned facts rather than asking a
worker to invent infrastructure. Build or refresh the tracked repository
context with `factory context build --root .`, keep product and architecture
guardrails in the owner-controlled Opinion Dock, and put the exact compiler,
schema, policy, or vendor CLI checks in the reviewed verifier bundle. A worker
can propose code; it cannot replace a declared identity provider, rewrite a
money representation, or treat undocumented provider behavior as proof merely
because its own output says so. These are supervised constraints: the mission
owner still selects and approves them.

## Graph Ops visibility

Graph Ops reads verifier sessions as a separate lane. A new session is shown as
`runtime-unattested` until independently supplied evidence is verified. This is
deliberate: a visual graph makes the delivery state easier to follow; it does
not turn a local contract into proof that a host, Kubernetes namespace, or
external runner actually honored it.

## Current boundary and extension path

The delivered slice is the contract and deterministic L1/L2 evidence surface.
It does not ship cron/webhook execution, autonomous prompt tuning, persistent
runtimes, Kubernetes staging, network enforcement, or secret injection. Those
are future adapters only after they can emit independently auditable runtime
attestations and remain under explicit human-controlled or supervised release
gates.
