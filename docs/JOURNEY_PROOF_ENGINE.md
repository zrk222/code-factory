# Journey Proof Engine

Code Factory's Journey Proof Engine checks whether the product journey that was
declared is the journey that the runtime actually exposed. It is local,
provider-neutral, and deterministic: browsers, APIs, CI systems, and external
test runners may supply observations, but none receives approval or release
authority.

## What it adds

### Journey Reality Graph

`factory journey reality` compares declared and observed states, transitions,
requirements, outcomes, and SHA-256-bound runtime artifacts. It reports exact
missing, unexpected, and stale items. It does not ask a model to guess whether
two differently named states mean the same thing.

### Rich Failure Capsules

`factory journey capsule` preserves the failed step, at most one adjacent step
on each side, a closed failure classification, workspace-contained artifacts,
and separate unverified hypothesis and repair fields. It writes a JSON receipt
and a reviewer-friendly Markdown capsule without claiming a root cause.

### Stateful Workflow Proof

`factory journey workflow-proof` verifies the complete workflow rather than
isolated green tests. Every consumed value needs one earlier producer with the
same hash. Every created side effect needs a later successful cleanup, and each
cleanup needs a passing idempotency probe.

### Proof-Gated Healing

`factory journey heal-verify` admits a candidate repair for review only when:

- the patch and changed paths are SHA-256-bound and allowlisted;
- role, label, route, and state anchors retain semantic identity;
- previously covered journeys remain covered;
- the positive command exits zero; and
- the adversarial negative mutation exits non-zero.

A negative command that also passes is a hollow healing proof and fails closed.

## Human and autonomous modes

The same proof engine supports two explicit modes:

- `human_controlled` forbids an agent command. It verifies the prepared repair
  and returns `HEALING_HUMAN_REVIEW_REQUIRED`.
- `supervised_auto` permits one to three no-shell attempts by an explicitly
  identified local command. Code Factory snapshots the workspace before and
  after every attempt, stops on the first scope escape, and returns
  `HEALING_AUTO_AWAITING_PROMOTION` only after the proof succeeds.

Neither mode grants final approval. Graph Ops can create an inert manifest
template, but a separately reviewed terminal must run it.

## The agent is audited too

Every supervised attempt produces a separate
`factory.agent-work-audit.v1` receipt. FactoryLine—not the worker—binds:

- the declared agent identity and argv digest;
- before and after workspace digests;
- exact changed paths and scope verdict;
- the agent, positive, and negative-mutation results; and
- one closed audit outcome and, for a failed outcome, one classification from
  Code Factory's closed `FailureClass` taxonomy.

The receipt stores hashes of bounded stdout and stderr rather than raw,
potentially sensitive logs. Worker approval is always `false`.

## BYOK and managed execution

BYOK/local execution is the default OSS path: private, provider-neutral, and
without hidden token markup. A managed service can later supply hosted keys,
usage controls, audit retention, team policy, support, and predictable billing.
Both paths must produce the same inputs and pass the same independent proof
engine; billing or provider choice cannot weaken the verifier.

## Read-only inspection

```bash
factory journey status --root . --json
```

MCP clients can call `factory.journey_status`. Graph Ops projects only
hash-verified receipts and links Agent Work Audits to their healing decisions.
Both surfaces expose `JOURNEY_STATUS_READ_ONLY` and cannot run agents, apply
repairs, approve, merge, publish, deploy, sign, message, access credentials, or
grant connectors.

## Receipt location

Receipts are written atomically under `.factory/journey-proof/`. Each receipt
contains a canonical `receipt_sha256`, an all-false authority map, and the exact
decision facts needed for offline review.
