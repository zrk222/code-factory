# Code Factory 0.46.0 — independent proof for agent handoffs

AI coding agents can report a completed task and a green test suite. This
release gives teams a separate way to inspect whether the handoff stayed bound
to the intent that was approved before coding began.

## What changed

- **Agent Proof Bridge** imports a compact, hash-only handoff from Eve, Junie,
  Grok Build, CodeRabbit, Devin, or a generic client. It checks a typed acyclic
  workflow DAG, source preconditions, contract-scoped paths, real before/after
  artifacts, provider-declared tool manifest and checkpoint hashes, and resume
  continuity. CodeRabbit and Devin profiles bind only supplied local handoff
  facts; the bridge never contacts a provider or proves provider identity.
- **Oracle Firewall binding** is mandatory. If the sealed intent contract is
  changed or stale, the bridge receipt and any derived worklog draft fail closed.
  The importer never accepts raw prompts, source bodies, URLs, credentials, or
  provider tokens.
- **Atomic handoff template** gives an Atomic workflow or another connected
  agent the exact, secret-free envelope shape to fill after the Oracle Contract
  is sealed. `factory atomic template --json` is an onboarding aid only: it
  does not create a workflow, contact Atomic, start or resume a run, or grant
  any authority.
- **Proof Worklog** makes a concise, immutable local draft from valid receipt
  summaries. It is always review-required and has no Jira, GitHub, Linear,
  Slack, messaging, deployment, or approval capability.
- **Clearer grilling ladder** makes the decision path explicit: intent,
  forbidden behavior, negative case, PRD, Oracle Contract, diff review, and
  independent challenge. A passing worker-authored test suite alone is not a
  release decision.
- **Operations Control** binds local Git isolation, a failed reproduction and
  bounded retry budget, a reviewable change envelope, appropriate proof tier,
  declared architecture zones, and pinned local repository heads. A mismatch
  fails closed; the receipt never creates a worktree or starts work.
- **Session Trace** adds explicit hash-linked harness continuity: each local
  event names its declared session and stage, input/output hashes, sealed
  Oracle Contract, evidence hashes, and predecessor receipt. It is not a claim
  of provider identity or actual execution.
- **Proof-gated Repair Loop** makes a failure reviewable as an exact `E_` issue,
  affected obligation, human-authored potential consequence, observed
  reproduction, candidate hash, positive and negative independent re-check,
  and named human review. It never guesses a repair or self-approves it.
- **Multi-repo Coordination + Domain Ontology** add a deterministic pinned-head
  dependency order and a small human-approved vocabulary for concepts,
  invariants, relationships, and owners. Both are local planning checks—never
  hidden orchestrators.
- **Shared protocol enums** centralize the existing wire values for provenance,
  rule effect, autonomy, provider state, declared isolation, workflow roles,
  evidence tiers, lifecycle stages, repair consequences, and Mission Control.
  Existing JSON manifests and receipts retain their exact string values.

## For individual developers

Start with `factory first-proof`: ask whether the test can actually fail.
When an agent is involved, import only a reviewed local handoff after the
intent is sealed. The bridge is evidence for your review—not automation you
need to trust.

## For teams

Graph Ops now shows the path from the sealed contract through the declared
agent workflow and before/after evidence to a review-required worklog draft.
It does not identify an external provider, prove sandboxing, run an agent,
resume a checkpoint, post an update, or approve a change.

```bash
pip install factoryline-code-factory==0.46.0
factory agent-bridge template --provider eve --json
factory agent-bridge template --provider coderabbit --json
factory agent-bridge template --provider devin --json
factory agent-bridge import --root . --envelope .factory/agent-envelope.json --json
factory worklog draft --root . --contract .factory/oracles/contracts/example.json --json
factory operations-control template --json
factory lifecycle template --json
factory repair-loop template --json
```

All commands are local. Importing evidence never grants approval, merge,
publication, deployment, signing, messaging, credential, or connector authority.
