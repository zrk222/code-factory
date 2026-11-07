---
title: Code Factory
emoji: 🏭
colorFrom: yellow
colorTo: gray
sdk: static
app_file: index.html
thumbnail: https://raw.githubusercontent.com/zrk222/code-factory/main/docs/assets/github-social-preview-1280x640.png
tags:
  - developer-tools
  - ai-agents
  - devops
  - software-quality
  - design-review
  - ui-quality
  - mcp
  - model-context-protocol
  - cursor
  - opencode
  - local-first
pinned: false
license: apache-2.0
short_description: Audit code, review evidence, and resolve defects.
---

# Code Factory

## Code Factory 0.49.6

Governance infrastructure for high-stakes agentic workloads.

[Verified wheel](https://huggingface.co/spaces/zrk222/code-factory/blob/24d51e618d685618725a850ba34be6a7df88a6d9/factoryline_code_factory-0.49.6-py3-none-any.whl) ·
[PyPI](https://pypi.org/project/factoryline-code-factory/0.49.6/) ·
[GitHub release](https://github.com/zrk222/code-factory/releases/tag/v0.49.6) ·
[Zenodo](https://doi.org/10.5281/zenodo.24029905)

The exposed N443-38 replay measured **88.24% decided actionable precision**
(30/34), up from 85.71% on the same observed cases. All 30 original true
positives were retained. The replay covered 37 of 38 cases, with two unclear
labels and a timeout on case 005.
[Case ledger](https://github.com/zrk222/code-factory/releases/download/v0.49.6/original38-regression-0.49.6.json)

The original sealed reference measured 83.33% among 36 decided alerts and
78.95% across all 38 cases. Two AI reviewers supplied the labels.

### What’s new in 0.49.6

1. **Pre-PR review.** `factory change pre-pr <manifest>` combines candidate source, planned checks, oracle evidence, and feature verification in one receipt. Add `--execute` to run the declared checks.
2. **Repair continuity.** `factory senior fix` returns `NO_PROGRESS` for a repeated failed candidate and `STEP_BACK` when the round budget is spent. The default budget stops before a fourth round.
3. **Incident intake.** Reviewed incidents produce source-bound regression packets marked `EXPOSED_NOT_EXECUTED`. Replay evidence records what was exercised.
4. **Scan evidence.** Native scans bind collection receipts before sealing. Collection drift marks the evidence incomplete and requires a fresh seal.
5. **CLI and editors.** `factory home` prints a local invitation to star the repo. Editor releases are VS Code and Open VSX 1.3.3 and JetBrains 1.3.4.

### The complete factory

- **FactoryLine** Coordinates local audits, evidence, and review decisions.
- **ForgeLine** Builds scoped changes and challenges their checks.
- **SpecLine** Defines the intent, requirements, and acceptance criteria those checks must prove.

### Current editor views

- VS Code and Open VSX 1.3.3 show local evidence and source locations in Explorer.
- JetBrains 1.3.4 carries forward saved-file synchronization before local
  commands and starts Factory Studio in the background.

The four annotated captures use the released interface and a fictional local
workspace. Graph Ops reports one planted finding from one scanned file.
Runtime evidence remains incomplete in the example.

![Factory Studio Product Mission draft with intent and review callouts](https://github.com/zrk222/code-factory/releases/download/v0.49.6/studio-product-mission-0496.png)

![Graph Ops guide for choosing the next proof](https://github.com/zrk222/code-factory/releases/download/v0.49.6/graph-ops-proof-guide-0496.png)

![Graph Ops local scan with source coverage and incomplete evidence](https://github.com/zrk222/code-factory/releases/download/v0.49.6/graph-ops-findings-0496.png)

![Expanded Graph Ops finding with its source line and rationale](https://github.com/zrk222/code-factory/releases/download/v0.49.6/graph-ops-finding-detail-0496.png)

## Audit workflow reference

- **Fixed:** local editor evidence now distinguishes missing, incomplete,
  unavailable, failed, and stale lanes instead of presenting inventory as a
  complete audit.
- **Changed:** Junie taxonomy now maps a diff to bounded checks, repair steps,
  reruns, and independent specialty AI review.
- **Added:** project-neutral `factory audit workflows` contracts with
  hash-bound candidate and execution evidence; VS Code/Open VSX 1.1.0 evidence
  tree; JetBrains 1.1.0 CF + ForgeLine tab; and native OpenCode 0.1.0 plugin
  with bounded session hooks.
- **Candidate detection fixes:** flags tests without a local assertion,
  constant-true assertions, and reflexive comparisons. Explicit tenant-read
  contracts check the declared `tenant_id` parameter binding.
  This seeded local demonstration shows the workflow using a finding and a
  repaired case. It applies the declared tenant-read contract to sample inputs
  and illustrates a review flow; it is not a release certification.
  CI verification is still required.

These are source preview targets until each provider confirms publication.

Specialty AI audit evidence is available in [the prior reviewed change and findings](https://github.com/zrk222/code-factory/pull/131#issuecomment-5980528354). That review applies to its exact source snapshot, not subsequent detection fixes. Test and CI receipts are separate evidence linked in the same change.

The preview highlights audit progress, actionable repair tasks, source-bound evidence and specialty AI review. It is a static walkthrough, not a hosted repository scanner. CF pattern/guard-path audits need project policy; its security scan covers Python ASTs. ForgeLine repo-wide QA is static inventory. Agent review does not establish exhaustive native scanner coverage: Gitleaks per-file accounting remains incomplete.

The updated Graph Ops capture in this Space shows the new **Audit and test
results** panel. It labels native deep-scan state, evaluated deep-audit
receipts, six runtime lanes, and individual JUnit test cases separately. Run
`python -m pytest --junitxml=.factory/test-reports/pytest.xml` in a local
workspace to populate its test list. The report remains explicitly unbound to
the current candidate; missing, invalid, or over-limit reports do not become a
passing run. The panel can search every recorded case in a bounded report of
up to 10,000 tests, starting with eight cases and loading 20 more per action.


Code Factory + ForgeLine (CF/FL) is now a robust, local-first code-audit
factory spanning requirements, architecture checks, Python AST security
analysis, behavioral test evidence, workflow integrity, specialty AI review,
and actionable repairs. Unsupported or missing evidence remains visible and
does not become certification.

The current source preview connects the original request, agent handoffs,
verification routes, current receipts, and human review. It also makes stale
repair loops and missing evidence easier to spot. Six audit lanes stay in the
core path; local receipts support review but do not approve releases.

This is the browser preview for
[Code Factory](https://github.com/zrk222/code-factory), an open-source,
local-first proof layer for AI-assisted code.

> **Audit code. Review evidence. Resolve defects.**

**First Proof is one starter example within the larger audit system.** Here it
is a local setup demonstration: run `factory first-proof --root .` to check the
setup and receive a local receipt; it does not assess repository code. Run
`factory scan --root .` for a repository assessment. First Proof writes its
receipt under `.factory/adoption/first-proof/`; project source is not uploaded
by this workflow.

- **Individual developer or vibe coder:** learn what a real negative control
  looks like before trusting an AI-generated test.
- **Senior developer or team:** wrap an admitted agent run, record its exact
  file delta, run declared validators, and review hashes and bounded facts—not
  retained prompts or raw model output.
- **Agent workflow team:** import an explicit workflow envelope and verify its
  typed DAG, scoped handoffs, checkpoint continuity, source bytes, resume
  lineage, and sealed intent binding without giving the workflow release
  authority.
- **App or SaaS builder:** storyboard the intended experience, verify identity
  through revocation, and run 30 exact-build Apple policy/rejection-regression
  gates before submission. Missing and unclassified evidence stays blocked.
- **Platform or assurance team:** evaluate policy gates, evidence packets,
  expiring exceptions, and tenant boundaries in a controlled pilot. Code Factory
  has Production/Stable package status; this is not an SLA, compliance certification, customer-reference,
  or procurement-readiness claim.

### Common pain points, addressed without hidden authority

- **"The test passed, but the app still broke."** Reality Check and Gauntlet
  retain declared negative cases and label hollow or blocked proof rather than
  converting a green result into a release claim.
- **"The agent picked a direction before anyone agreed on the intent."** Intake
  Grill binds a named framework, exact intent, observable acceptance evidence,
  and effects boundary before a mission can require it.
- **"We keep retrying the same failed repair."** Proof-Delta requires a changed
  candidate and fresh evidence or deliberately stops as no-gain.
- **"Trust in our coding agent keeps increasing by habit."** Earned Autonomy
  uses governed evidence and automatic severe-failure demotion; it does not
  identify an agent or grant it execution permissions.
- **"A review has comments but no common proof picture."** Graph Ops and the
  local MCP surface project receipts, Proof Debt, and one next action without
  enabling merge, release, deployment, source upload, or credential access.
- **"The final agent claim is green, but its workflow may have drifted."** The
  Atomic Proof Adapter rejects cycles, undeclared handoffs, scope escape,
  changed source bytes, and resume drift; it does not execute the workflow.

Read the [Teams and Enterprise Operations Manual](https://github.com/zrk222/code-factory/blob/main/docs/ENTERPRISE_TEAMS_OPERATIONS.md)
for role boundaries and the optional [Prestige Design Review](https://github.com/zrk222/code-factory/blob/main/docs/PRESTIGE_DESIGN.md)
for a purpose-led UI review lane. Neither feature certifies conversion,
accessibility, or production readiness.

The standalone [AppForge App Review Gate](https://github.com/zrk222/code-factory/blob/main/docs/APPFORGE_APP_REVIEW_GATE.md)
is designed to save avoidable review/rework waiting time by catching purchase,
restore, iPad, screenshot, reviewer-access, privacy, metadata, accessibility,
and export gaps before submission. It does not guarantee Apple approval.

**For a specific risky behavior:** use the supervised
[Gauntlet](https://github.com/zrk222/code-factory/blob/main/docs/GAUNTLET.md)
to run only human-written, named-admitted local E2E sabotage cases and save an
offline-verifiable Survival Card. A card shows survived, hollow, and blocked
declared cases; it is not a production-readiness or release certificate.

The canonical Python package is
[`factoryline-code-factory`](https://pypi.org/project/factoryline-code-factory/).
Core release `v0.46.4` is published under the repository's stable Zenodo concept DOI at
[Zenodo](https://doi.org/10.5281/zenodo.21381405).

### New: declared Senior Attention before review

When the change is harder than a green check can explain, a team can add a
human-declared, hash-bound Change Profile. Engineering Judgment compares those
facts with named active decisions and shows the smallest required attention:
routine, domain, specialist, or architecture. It exposes novel declared
boundaries and decision drift; it does not inspect source code to guess intent,
run proof, approve a change, or release anything.

Use the same local proof context from Cursor or OpenCode through the documented
[MCP connection](https://github.com/zrk222/code-factory/blob/main/docs/AI_CLIENTS.md).
The client connection is local and read-only; it does not upload source or
grant provider, credential, deployment, or publishing authority.

### LangGraph resume assurance

For a LangGraph agent flow, use the free local
[LangGraph Assurance Bridge](https://github.com/zrk222/code-factory/blob/main/docs/LANGGRAPH_ASSURANCE.md)
after your own test harness records a normal path and a forced-resume path. It
compares sealed, hash-only lineages and emits either resume parity or a
shareable first-divergence incident capsule. The local MCP tool and opt-in
GitHub Action consume recorded receipts; neither invokes a graph, mutates a
checkpoint, or replays a side effect.

Use Code Factory alongside CodeRabbit or another AI reviewer when a pull
request needs explicit evidence as well as suggestions. The opt-in
[GitHub Proof Review](https://github.com/zrk222/code-factory/blob/main/docs/GITHUB_PROOF_REVIEW.md)
adds one neutral, commit-bound Proof Review Check and stable walkthrough beside
other review comments. It requires no CodeRabbit account or credential, never
imports AI comments as proof, and never auto-approves or merges a pull request.

### Plan-to-Proof and Teams

`factory plan verify` compares a strict, human-approved agent plan with the
exact changed paths and existing Diff-to-Proof facts. It exposes scope drift,
missing declared test-path changes, deep-review routing, and proof debt as
deterministic obligations. It does not execute tests, read AI transcripts, call
a provider, change branch protections, approve, merge, publish, or deploy.

Before a PRD becomes a scaffold, run `factory prd grill PRD.md --root .` for a
capped, source-bound clarification sheet with recommendations and answer stubs.
It never rewrites the PRD, invents answers, calls a model, or authorizes a
build. Read the full [PRD Grill guide](https://github.com/zrk222/code-factory/blob/main/docs/PRD_GRILL.md).

### What's new in 0.34.0

Merge Evidence Dossier joins a commit-bound Proof Review with supplied,
schema-validated policy snapshots. It makes ruleset weakening visible before a
human merge decision, accepts only named expiring exceptions bound to the exact
commit and policy, and never reads or alters live GitHub settings. Graph Ops
now also exposes a Proof Observatory with direct coverage, drift, and
blocked-gate visuals while execution remains locked.

### Graph Forensics and ProofSearch (0.32.0)

Graph Forensics compares sealed execution lineage, locates the first semantic
divergence, traces its causal path, and detects stale state, conflicting writes,
or repeated side effects without replaying them.

ProofSearch then compares 2 through 12 supplied, hash-bound repair candidates.
It rejects failed proofs, surviving mutants, scope escapes, test weakening, and
error suppression before ranking eligible candidates. Graph Ops shows every
candidate, exact rejection reasons, the verified winner, proof runtime, and
measured-or-unavailable savings. Applying, merging, publishing, and deploying
remain locked.

Time, token, and cost savings appear only when an exact paired baseline exists;
productivity remains unavailable without separate measured evidence.

### Native E2E proof and Team Pilot readiness (0.31.0)

`factory e2e verify` accepts an approved positive/negative command-pair
manifest and proves the negative path can fail. A negative command that exits
zero is recorded as `HOLLOW_E2E_TEST`, rather than being treated as a passing
E2E check. The native local gate uses explicit argument vectors and does not
provision a browser grid, call a vendor, repair source, or claim readiness.

`factory team-pilot readiness` writes a hash-bound owner-review receipt only
when up to three human-selected, customer-managed reference partners have five
complete local operating decisions. It cannot enroll a partner, issue terms,
collect payment, provision access, or activate a service.

### Plan-to-Proof Review (0.30.0)

`factory plan verify` compares a strict, human-approved agent plan with exact
changed paths, declared test paths, review tiers, and existing Diff-to-Proof
facts. It writes explicit Proof Debt for scope drift, missing declared tests,
deep-review routing, and source claims without evidence. The optional GitHub
adapter publishes one neutral, commit-bound Check and stable walkthrough; it
does not execute tests, call a provider, approve, merge, publish, deploy, or
claim readiness.

### Independent verification (0.27.0)

`factory verifier` binds a worker result to distinct verifier evidence,
immutable check files, deterministic checks, and hard declared budgets. It
rejects self-grading and byte drift, then Graph Ops shows the session as
`runtime-unattested` until independently supplied evidence is verified. Code
Factory validates the contract; an external supervised runner must enforce
runtime sandbox, network, and credential boundaries.

The public visual set uses actual Factory Studio captures and the current
FactoryLine identity asset. It is product behavior evidence, not measured time,
token, cost, productivity, conversion, Marketplace approval, or
production-readiness evidence.

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

## Native agent-harness workflows

The native harness keeps incident checkpoints for recovery, binds review
context shards to source, and compares candidate repairs without applying them.
Budgeted Jev triage keeps unprocessed incidents visible as pending, not assessed.
Parallel audits are opt-in and require a signed policy declaring work
non-mutating and resource-safe; serial remains the default, and the declaration
does not prove isolation. Optional activation experiments call only hooks
explicitly registered by the caller. Their observations are experimental, not
model certification or accuracy evidence. The source taxonomy and manifest define the same routes for
Junie while keeping execution and identity limits visible.

## Native scanner adapters

**Fixed:** native scanner controls require vulnerable and safe results bound to
image, profile and source hashes. Missing evidence remains incomplete.
**Changed:** agents use one `factory scan --deep` overview and explicitly
configured native workers selected for the project's languages and risks.
JavaScript/Actions workers verify bundled compiled queries rather than rebuilding
them, and receipt discovery skips explicit file checks for unrelated logs.
**Added:** CodeQL JavaScript/TypeScript interprocedural analysis, GitHub Actions
security-extended analysis, and eight Python/JavaScript/TypeScript Semgrep
rules including local taint tracking. CodeQL controls require native flow
evidence; Semgrep community output does not establish cross-file coverage.

## Smaller models, stronger quality workflows

CF/FL is designed to guide smaller LLMs toward frontier-like coding performance
through deterministic workflows, independent audits and evidence-driven repair.
Sealed task packets keep requirements, scope and acceptance checks explicit.
This is the design objective; model parity and cost savings require a paired
benchmark and are not established by the current attribution metric.
