# Code Factory overview

Code Factory is a local-first software assembly workflow. Give it an outcome,
choose a target, and it produces an inspectable application-shaped starting
state rather than pretending that generated code is already production ready.
The same workflow expresses requirements, value slices, missions, tests,
approvals, and validation evidence as a Product Graph so a team can see what is
known, what is missing, and the one fact-derived next action.

## What it does

- **Gets a project moving quickly.** `factory mvp "..."` provides an
  outcome-first route to a contained MVP. `factory create` supports web, mobile,
  API, CLI, worker, MCP, and agent-UI starters.
- **Clarifies the contract before automation compounds it.** `factory prd grill
  PRD.md --root .` creates a capped, source-bound question sheet with answer
  stubs. It does not rewrite the PRD, invent answers, or authorize a build.
- **Makes delivery state legible.** Factory Studio, Graph Ops, and the VS Code
  and JetBrains integrations present requirements, gates, proofs, and blocked
  work in one local, read-only view.
- **Explains why graph runs diverge.** Graph Forensics verifies hash-sealed
  state lineage, identifies the first semantic divergence, detects stale reads,
  unsafe parallel writes, and repeated effects, then previews the smallest
  human-reviewed recovery fork without executing it.
- **Chooses the smallest repair that still carries complete proof.**
  `factory proofsearch` verifies supplied patch and receipt hashes, required
  gates, mutation results, scope, and safety declarations across 2 through 12
  candidates, then explains one deterministic winner without applying it.
- **Separates creation from verification.** The Verifier Plane hash-binds a
  mission, candidate tree, immutable verifier bundle, independent identities,
  evidence, deterministic checks, and declared hard budgets. It validates a
  supplied result but does not claim to execute or sandbox the runner.
- **Gives agents bounded context.** The local stdio MCP server exposes the same
  Graph Ops facts, impact, and next action without execution or external
  authority. Every generated starter also includes a deterministic Mermaid
  output map.
- **Turns explicit agent workflows into independently reviewable evidence.**
  The Atomic Proof Adapter verifies a typed acyclic stage graph, scoped
  capabilities and handoffs, checkpoints, source preconditions, and resume
  lineage before binding the result to the current Oracle Contract. It imports
  evidence only; it does not execute the workflow or inherit its authority.
- **Keeps teams and agents on one visible control plane.** Operations Control,
  Session Trace, Proof-gated Repair Loop, pinned multi-repo coordination, and
  an optional human-approved Domain Ontology make the exact evidence chain
  visible in Graph Ops and read-only MCP. Humans retain approval; an agent
  cannot weaken intent, alter thresholds, self-approve a repair, or change a
  repository through this surface. See [Control Plane](CONTROL_PLANE.md).
- **Protects the definition of done.** Coverage and completion claims require
  non-hollow tests and verifiable receipts. A fresh scaffold remains explicitly
  blocked until real evidence exists.
- **Avoids unnecessary repeat work.** Content-addressed proof reuse can route a
  matching read-only validation to RUN, REUSE, SKIP, or BLOCK, preserving the
  reason and paired savings evidence instead of silently skipping a check.
- **Turns a diff into a reviewable proof plan.** `factory change review` joins
  explicit change impact, stale proofs, coverage gaps, and existing risk policy
  into one analysis-only reviewer packet and Mermaid map.
- **Makes the next proof easy to see without turning memory into authority.**
  `factory memory brief` projects explicit changed-path evidence into capped,
  explanatory next actions with redacted continuity facts and observed local Git
  contribution context. It never runs a proof, recalls memory bodies, or treats
  Git authors as verified project seats.
- **Adds deterministic evidence to a GitHub PR without replacing its reviewer.**
  `factory github proof-review` binds the current Diff-to-Proof Review to one
  exact commit, an advisory neutral Check, and a stable walkthrough. It can
  coexist with CodeRabbit or another AI-review surface, but never imports their
  credentials or comments as verification evidence.
- **Makes supplied policy weakening visible before a human merge decision.**
  `factory github assurance-dossier` compares schema-validated policy exports,
  binds them to a Proof Review and exact commit, and projects unresolved high
  drift into Graph Ops. It never reads or changes live GitHub policy.
- **Makes an approved agent plan reviewable after the code exists.**
  `factory plan verify` binds a strict, named human-approved plan to the exact
  changed paths, preserves Diff-to-Proof facts, and emits Proof Debt for scope,
  declared-test, deep-review, and existing evidence obligations. It does not
  call a test executed, interpret an AI summary as proof, or alter branch policy.
- **Proves whether an explicit E2E check can reject a declared failure.**
  `factory e2e verify` runs a human-approved local positive/negative argv pair,
  records `HOLLOW_E2E_TEST` when the negative case exits zero, and emits a
  hash-bound proof packet only to an explicit output directory. It has no hosted
  testing-vendor, browser-grid, or external-upload dependency; the no-egress
  field is a declaration, not an unenforceable isolation claim.
- **Makes UI design reviewable without pretending it is proven.** The optional
  [Prestige Design Review](PRESTIGE_DESIGN.md) adds purpose-led design briefs
  and visible audit artifacts for hierarchy, responsive behavior, affordance,
  consistency, and declared tokens. Its deterministic findings can inform a
  gate; its heuristic critique remains a human review prompt.
- **Keeps supervised repair context exact.** `factory repair scope` seals one
  explicit Change List's paths, current file hashes, and measured bytes, then
  `factory repair candidate` rejects a textual patch that crosses that scope.
  Neither command runs an agent, estimates credits, applies a patch, or replaces
  independent verification and human review.
- **Makes release blockers visible before dispatch.** `factory release integrity`
  checks local artifact fan-in, trusted PyPI publishing, and protected
  marketplace boundaries without touching credentials or publication state.
- **Scales without blurring authority.** Capability packs, signed receipts,
  approval boundaries, and the optional hosted adapter support team and
  enterprise workflows while keeping publishing, credential access, approvals,
  deployments, and external messages human-controlled.

## Typical path

```powershell
pip install factoryline-code-factory==0.46.0
factory mvp "Build an approval tracker" --root .
factory studio --root .
factory graph ops --root . --mermaid
factory graph forensics --baseline good.lineage.json --candidate bad.lineage.json --json
factory proofsearch verify .factory/proofsearch/repair.evaluation.json --root . --json
factory verifier progress .\attempts.json --json
factory change review --root . --base origin/main
factory memory brief --root . --json
factory github proof-review --root . --base origin/main --head-sha abcdefabcdefabcdefabcdefabcdefabcdefabcd --json
factory release integrity --root . --json
```

Start with the local MVP, open Studio to inspect its state, then use Graph Ops
to follow relationships and impact before choosing the next proof. The visual
surfaces do not execute commands or take external actions; they reveal the
evidence and the next action that the local facts support.

## Who it is for

For a developer new to delivery automation, Code Factory provides a guided
path from outcome to an honest MVP. For experienced developers and teams, it
provides a shared, auditable model of delivery state, deterministic validation
receipts, reusable proof routing, and a Plan-to-Proof handoff for AI-created
diffs. In both cases, speed never replaces the evidence needed to certify work.
Read the concise [Teams and Enterprise Operations Manual](ENTERPRISE_TEAMS_OPERATIONS.md)
for roles, rollout order, evidence artifacts, and the explicit non-delegable
controls.

The [commercial packaging guide](COMMERCIAL_PACKAGING.md) separately explains
what is usable now (the free local core) and what remains proposed or
discovery-only (Team Proof Hub, Enterprise Assurance, and a managed runner).
It does not activate a purchase, service, or Marketplace offer. Selected
design partners can use the local [Team Pilot readiness gate]
(TEAM_PILOT_LAUNCH.md) to prepare owner-review evidence for a customer-managed
reference pilot, not a managed-service launch.

## Boundaries that matter

Code Factory is local by default. It does not discover credentials, publish,
deploy, sign, approve, message, or grant connectors merely because a graph or
UI exists. Those actions stay behind explicit human-controlled or supervised
boundaries. Savings reports keep unknown token or cost values unknown; they do
not invent productivity claims. The Verifier Plane also keeps its boundary
explicit: it proves supplied byte bindings and declared identities, while an
external runner must prove any runtime isolation or egress policy.

Next: follow [Start Here](START_HERE.md), explore [Unified Graph Ops](GRAPH_OPS.md),
connect the [Local MCP inspection server](MCP.md), or see the
[Target Compiler and Factory Studio](TARGET_COMPILER.md), or review the
[Verifier Plane](VERIFIER_PLANE.md).

### Contradiction gate (0.26.0)

`factory cdte scan` detects architecturally incompatible NFR pairs before any
code is generated, by deterministic lookup over a decision table. No model is
called. Analysis is tiered `measured` / `modeled` / `structural`, and a modeled
analysis whose inputs are absent is withheld rather than estimated. Critical and
high severity conflicts engage the fail-closed boundary and pause the line at
`nfr_conflict`.

### Habituation gate (0.26.0)

`factory habituation status` calibrates the human approval signal against each
reviewer's own baseline and escalates: surface, second approver, fail closed.
Blocking is refused until blind-spot re-review outcomes correct the proxy.
Public exports carry distributions only, never per-reviewer rows.
