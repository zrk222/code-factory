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
short_description: Trace graph failures. Compare proven repairs before review.
---

# Code Factory

This is the browser preview for
[Code Factory](https://github.com/zrk222/code-factory), an open-source,
local-first proof layer for AI-assisted code.

**For solo builders:** generate a local MVP, then make the next proof gap
visible. **For teams:** keep AI-created diffs within an approved scope, route
deep changes to named reviewers, and surface explicit Proof Debt before a human
makes a merge decision. Read the [Teams and Enterprise Operations Manual](https://github.com/zrk222/code-factory/blob/main/docs/ENTERPRISE_TEAMS_OPERATIONS.md).

**For UI work:** add the optional [Prestige Design Review](https://github.com/zrk222/code-factory/blob/main/docs/PRESTIGE_DESIGN.md): a purpose-led design brief plus visible review artifacts for hierarchy, responsive behavior, affordances, consistency, and declared design tokens. It informs review; it does not claim conversion, accessibility certification, or production readiness.

**Generate a local MVP, then catch hollow tests before review.** Start from a
plain-language outcome, a fuzzy PRD, or a risky diff. Code Factory keeps the
proof path visible and does not call a starter production-ready before relevant
evidence exists.

The canonical Python package is
[`factoryline-code-factory`](https://pypi.org/project/factoryline-code-factory/).
Release `v0.35.0` is archived under the repository's stable Zenodo concept DOI at
[Zenodo](https://doi.org/10.5281/zenodo.21381405).

Use the same local proof context from Cursor or OpenCode through the documented
[MCP connection](https://github.com/zrk222/code-factory/blob/main/docs/AI_CLIENTS.md).
The client connection is local and read-only; it does not upload source or
grant provider, credential, deployment, or publishing authority.

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
