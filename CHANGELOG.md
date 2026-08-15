# Changelog

## 0.33.0 - 2026-08-15

- Add Evidence Frontier, a deterministic Graph Ops loop-planning receipt that
  ranks supplied next-evidence hypotheses by the repair-candidate pairs they
  separate. It binds a current ProofSearch evaluation, labels predictions as
  unverified, halts when no proposed experiment discriminates, and keeps command,
  workspace, checkpoint, approval, merge, publication, deployment, signing,
  messaging, credential, and connector authority locked.
- Add `factory proofsearch frontier plan|verify` and a Graph Ops Evidence
  Frontier lane with ranked experiment cards plus copy/export/guardrail controls.
  The Run control is visibly disabled; this release does not execute tests or
  claim time, token, cost, or productivity savings.

- Add ProofSearch, a deterministic counterfactual repair selector. It seals the
  first Graph Forensics divergence and exact Graph Impact proof slice, verifies
  2 through 12 hash-bound candidates, rejects failed proofs, surviving mutants,
  scope escapes, test weakening, and error suppression, then selects one
  minimum-risk/scope/runtime winner without applying it.
- Add the Graph Ops Counterfactual Arena with every candidate, exact rejection
  reasons, proof and mutation facts, winner rationale, evidence-bounded savings,
  decision export, guardrail validation, and visibly locked apply/merge/release
  controls.

- Add Graph Forensics: hash-sealed semantic lineage receipts, deterministic
  first-divergence and causal-cone analysis, stale-read/parallel-write/
  duplicate-side-effect findings, and a non-executing recovery-fork preview.
- Add `factory graph lineage-seal|lineage-mission|lineage-verify|forensics`
  plus Graph Ops and Factory Studio lineage/forensics lanes. The real forensic
  cockpit compares sealed runs, displays anomalies and causal impact, and adds
  a guarded Action Dock for dry-run preparation and policy validation.
  Checkpoint mutation, graph execution, side-effect replay, release authority,
  and unmeasured savings remain outside the feature boundary.

## 0.31.0 - 2026-08-14

- Add `factory e2e verify`, a local proof-by-sabotage gate that requires an
  approved positive command, negative mutation command, explicit argv, and
  declared artifacts. A negative command that exits zero produces
  `HOLLOW_E2E_TEST`; neither path is called proof by a green result alone.
- Add `factory team-pilot readiness|verify`, a hash-bound owner-review packet
  for at most three human-selected, customer-managed reference partners. It
  requires five non-secret operating decisions and rejects sellable, managed,
  anonymous, or widened pilot claims.
- Document staged Team Proof Hub packaging without calling it purchasable or
  activating a price, checkout, entitlement, onboarding, or managed service.
- Align release, citation, Hugging Face, and installation surfaces to the new
  version while preserving target-specific Marketplace moderation and
  credential gates.

## 0.30.0 - 2026-08-14

- Add `factory plan verify`, a deterministic Plan-to-Proof Review that compares
  a strict, human-approved agent plan with the exact changed paths, declared
  test paths, review tiers, and existing Diff-to-Proof facts.
- Add a content-addressed Proof Debt artifact for scope drift, missing declared
  test-path changes, deep-review routing, and source claims without evidence.
  It reports review obligations; it does not execute tests, read agent
  transcripts, call a provider, change source, approve, merge, publish, deploy,
  sign, or claim readiness.
- Extend the optional GitHub advisory Check so it selects Plan-to-Proof Review
  when `.factory/agent-plan.json` is present. It remains commit-bound, neutral,
  same-repository only, and compatible with CodeRabbit or other AI reviewers.
- Add the Enterprise and Teams Operations Manual and the optional Prestige
  Design Review lane: a purpose-led brief plus visible UI-review artifacts that
  inform human review without claiming conversion, accessibility certification,
  or production readiness.
- Refresh GitHub, PyPI, Hugging Face, VS Code, JetBrains, Zenodo, and release
  surfaces with the same solo-builder and team-operating model.

## 0.29.0 - 2026-08-13

- Add `factory github proof-review`, a local, deterministic adapter that
  validates a current Diff-to-Proof Review, binds it to an exact pull-request
  head SHA, and renders a neutral GitHub Check request plus stable Markdown
  walkthrough.
- Add the opt-in same-repository pull-request workflow. It can create or update
  one bounded comment and one neutral Check using only `contents: read`,
  `pull-requests: write`, and `checks: write`; it ignores fork PRs and never
  uses `pull_request_target`, writes source, approves, merges, or invokes a
  model.
- Document CodeRabbit as a complementary AI-review surface rather than a
  dependency or a copied feature. Code Factory neither requires CodeRabbit nor
  imports vendor credentials or AI comments into verification receipts.
- Update GitHub, PyPI, Hugging Face, VS Code, JetBrains, release, and
  community-draft surfaces with the evidence-versus-suggestions boundary.

## 0.28.2 - 2026-08-11

- Correct the FactoryLine VS Code Marketplace classification to the supported
  `Testing` category. This patch does not change FactoryLine runtime behavior,
  permissions, local-first data boundary, or the v0.28 review controls.

## 0.28.0 - 2026-08-08

- Add the Proof Review handoff for attention-first, structured review of the
  current diff and its local evidence.
- Add the Verified Repair Sandbox, which seals a native Change List scope and
  produces a local handoff without editing code, running tests, or invoking an
  AI runner.
- Add the Workspace Load Advisor for bounded project-shape and remote/WSL
  preflight observations without changing IDE settings or claiming a
  performance diagnosis.
- Ship release and editor documentation with the same explicit authority
  boundaries: local evidence is not a deployment, sandbox, or readiness claim.

## 0.27.0 - 2026-08-08

- Add the Verifier Plane: a hash-bound evidence contract that separates a
  worker from an independently declared verifier without giving either merge,
  publish, deploy, or credential authority.
- Bind the mission receipt, candidate-tree digest, immutable verifier bundle,
  exact worker receipt, verifier evidence, deterministic checks, and declared
  ceilings for attempts, wall time, tokens, and cost.
- Reject self-verification, non-fresh verifier contexts, candidate and verifier
  bundle drift, path escape, evidence drift, budget overrun, and a passing
  verdict that contains a failed deterministic check.
- Add `factory verifier session|verify|progress`. The progress command halts
  repeated exact deterministic failures for owner review instead of using an
  LLM judgment to keep retrying.
- Add a Graph Ops verifier-session lane. A session is labelled
  `runtime-unattested` until supplied independent evidence is verified; the UI
  does not misrepresent a local contract as host or container isolation.
- Document the boundary for LLM rubrics: they may add evidence but cannot
  override deterministic gates or authorize external effects.

## 0.26.0 - 2026-08-07

- Add the habituation gate: calibrate the human approval signal rather than
  trusting it. Every other gate receipts an outcome; none receipted the
  reliability of the signal that produced it, and the most important such signal
  is a human clicking approve.
- Measure scrutiny as review seconds per 100 changed lines and compare it only
  against the same reviewer's own human-authored baseline. There is no
  cross-reviewer comparison and no population norm.
- Withhold drift below five agent-authored reviews or five baseline reviews. A
  drift figure from a smaller sample is noise wearing the costume of a
  measurement.
- Escalate deterministically: surface the comparison, then require a second
  independent approver, then fail closed at `scrutiny_floor`.
- Refuse to block on an uncorrected proxy. Fail-closed requires blind-spot
  re-review outcomes to exist, because scrutiny time is a proxy for attention
  and a self-confirming proxy is not a gate.
- Select blind-spot re-reviews deterministically from the low-scrutiny half so
  an auditor can reproduce the sample without trusting this process. Re-review
  identity must differ from the original approver.
- Keep escaped-defect linkage `modeled` and withheld by default, with its
  assumptions printed and a stated minimum sample. It reports rates across a
  sample and never attributes a defect to an individual.
- Store reviewer identities as digests. Public exports carry distributions only,
  with no per-reviewer rows even pseudonymously.
- Add `factory habituation record|status|sample|resample|report`. `status` exits
  non-zero only when the gate actually blocks.

## 0.25.0 - 2026-08-07

- Add CDTE, the contradiction gate: a deterministic pre-build check that detects
  architecturally incompatible non-functional requirements before any code is
  generated. SpecLine removes ambiguity from a spec; CDTE removes contradiction.
- Detect conflicts by lookup over `factoryline/data/lethal_pairs.json`, a
  decision table. Detection calls no model, so the gate is reproducible, free to
  run on every assembly, and extended by a data change plus a table test rather
  than a prompt rewrite.
- Constrain incompatibility analysis to three declared tiers: `measured`
  (hash-bound benchmark), `modeled` (formula with printed assumptions), and
  `structural` (no numbers). A modeled analysis whose inputs the spec did not
  supply is withheld, never estimated. The conflict is still reported.
- Engage the existing fail-closed boundary on critical and high severity
  conflicts, pausing the assembly line at `nfr_conflict` with a continuation
  command instead of generating code against contradictory requirements.
- Require every override to name an approver and carry an expiry. Permanent or
  anonymous overrides are not recordable.
- Add `factory cdte scan|report|resolve`. `scan` exits non-zero when the gate
  engages so CI fails closed. `report` exports aggregate counts only, with no
  constraint text, run identifiers, or paths.
- Draft an ADR per conflict, tier-labelled, with the Decision section left for
  the author.
- Compute savings deltas in exact decimal arithmetic. Cash fields previously
  carried binary float artifacts such as `0.060000000000000005` into published
  receipts; they now carry `0.06`. Sub-cent costs are preserved.
- Update the GitHub, PyPI, Hugging Face, VS Code, JetBrains, and Marketplace
  listing surfaces with the contradiction gate and its evidence boundary.

## 0.24.3 - 2026-08-06

- Add PRD Grill: a deterministic, local clarification pass that writes a
  capped current question frontier, answer stubs, source evidence, deferred
  dependencies, and a verifiable source-bound receipt before PRD optimization,
  Product Graph compilation, or scaffolding.
- Preserve author control: PRD Grill never rewrites the source PRD, invents
  answers, calls a model, starts a build, or authorizes external effects.
- Update the GitHub, PyPI, Hugging Face, VS Code, JetBrains, and Marketplace
  listing surfaces with the PRD Grill workflow and its proof boundary.

## 0.24.2 - 2026-08-05

- Add optional, local-only post-success GitHub Star actions in the VS Code and
  JetBrains adapters; neither editor opens a browser or sends data without the
  user's explicit click.
- Add optional output-map attribution so a team can choose to credit the
  proof-first workflow in a public artifact without Code Factory posting or
  editing any file beyond the generated output map.
- Refresh the GitHub, PyPI, editor, Hugging Face, and community-launch copy
  around the outcome-first MVP path, source-bound receipts, and Graph Ops.
- Remove the internal JetBrains plugin-manager API from the star action, so
  the package verifies across the supported IDE matrix.

## 0.24.1 - 2026-08-04

- Publish the Marketplace Acquisition Kit: outcome-led listing copy, the
  two-minute first-use path, accurate tag guidance, and an IDE-native media
  capture gate.
- Add verified Factory Studio and Unified Graph Ops product-tour captures to
  the README, public landing page, and source distribution. They are explicitly
  not represented as JetBrains IDE screenshots.
- Add an observed-only Marketplace download-delta command and baseline. It
  leaves conversion and causal uplift unavailable without vendor analytics.
- Add a concise public product overview of the MVP path, proof boundaries,
  Graph Ops, proof reuse, team controls, and authority limits.
- Refresh the public Hugging Face surface and retain the pending JetBrains
  review, free-through-2026, and planned-2027 pricing boundaries.

## 0.24.0 - 2026-08-03

- Add bounded, read-only Unified Graph Ops across the CLI, Factory Studio,
  VS Code, and JetBrains integrations.
- Add `factory mvp` and an outcome-first Studio default so a novice can build a
  contained local web MVP before learning the full factory vocabulary.
- Add `factory graph impact` for exact changed-input-to-proof mapping and a
  stale-only rerun set; it never treats an unmatched path as safe.
- Link existing Product Graph, slice, mission, approval, completion, proof,
  gate-plan, trace, receipt, and artifact facts without replacing their source
  verification or authority boundaries.
- Add accessible lane-based visual inspection and one exact fact-derived next
  action; no time, token, cost, or productivity savings are claimed.

## 0.23.2 - 2026-08-03

- Add strict Core-5 agent contracts with canonical digests and execution rails.
- Require fresh-context creator/verifier attestations for mission completion.
- Reconcile run telemetry across receipts, traces, and meter observations without
  exposing feature names, prompts, paths, or raw logs in public summaries.
- Add provider capability, privacy, latency, context, cost, and output-contract
  constraints plus conditional Prestige UI validation.

## 0.23.1 - 2026-08-01

- Patch the two high-severity npm advisories in the VS Code build toolchain by
  resolving `brace-expansion` to 5.0.9 and `fast-uri` to 3.1.5.
- Fail pull-request and release packaging when npm reports a high or critical
  vulnerability.
- Preserve the extension's dependency-free VSIX and runtime authority; the
  affected packages are development-only packaging dependencies.

## 0.23.0 - 2026-07-31

- Add content-addressed read-only proof receipts and exact verification of
  inputs, outputs, command digest, toolchain, and environment.
- Add `factory proofs record|plan|verify|challenge` with fail-closed RUN,
  REUSE, SKIP, and BLOCK dispositions.
- Add automatic paired savings receipts for verified reuse observations while
  preserving unavailable token measurements as null.
- Add compact proof-plan receipts that omit source, commands, logs, prompts,
  credentials, and absolute workspace paths.
- Key IntelliJ workflow concurrency by commit SHA to collapse identical proof
  across eligible GitHub triggers.
- Add strict SpecLine and ForgeLine contracts, a proof mutation challenge, and
  grade-A feature QA evidence.

## 0.22.0 - 2026-07-25

- Add exact baseline-versus-Factory savings receipts for elapsed time, tokens,
  and cost, preserving unknown and negative results.
- Add aggregate-safe public savings exports that omit pair identifiers,
  evidence paths, and per-pair observations.
- Withhold productivity gain unless an equivalent outcome is explicitly
  asserted and bound to a SHA-256 evidence digest.
- Surface the same savings report in Factory Studio, VS Code 0.7.0, and the
  JetBrains plugin 0.7.0.

## 0.21.0 - 2026-07-24

### Added

- Added `factory continue [feature]` to resume the assembly line through safe
  local stages and stop at one explicit human boundary.
- Added Assembly mode to Factory Studio and continuation commands to the VS Code
  and JetBrains integrations.
- Added atomic per-run Assembly receipts and `factory metrics` privacy-safe
  aggregates. Missing token and cost observations remain explicitly unknown,
  and savings require a measured counterfactual baseline.

### Changed

- SSAT contracts are resolved consistently from `specs/`, the repository root,
  or the explicit adoption filename.
- Human-facing continuation output is compact; full stage detail is available
  with `--json`.

## 0.20.0 - 2026-07-20

### Added

- Added a transactional, hash-linked Product Mission graph with guarded roles,
  independent validation, human pause/revise/resume, hard budget exhaustion,
  release separation, Mermaid export, and optional LangGraph checkpoints.
- Added secret-free multi-provider BYOK policies and deterministic routing across
  CLI, Studio, VS Code, and JetBrains using environment-variable references,
  quality/cost rails, IDE allowlists, and cache-continuity hints.
- Added JetBrains Mission Operations for graph status, history, verification,
  export, guarded events, and provider routing with workspace containment and
  output redaction.
- Added `factory learning init|packet|propose|validate|promote` for task-specific
  AKU refinement with fresh worker contexts, exact milestone gates, independent
  validation, hash-bound evidence, and recorded human promotion.
- Added optional Harbor and Terminal-Bench result binding as local validation
  evidence without granting the external harness execution or promotion authority.
- Added bounded ASHA, Hyperband, and BOHB experiment contracts over the six
  harness control dimensions with correctness-first lexicographic ranking.

### Security

- Worker scratchpads and prior outputs are excluded from new worker packets;
  worker, validator, and promoter identities must be distinct.
- Unvalidated instruction candidates are inactive and cannot edit the
  owner-controlled Architecture Opinion Dock.

## 0.19.0 - 2026-07-19

### Added

- Added a supervised hosted tenant lifecycle with bootstrap platform authority,
  per-tenant OIDC/JWKS configuration, atomic group-to-role replacement,
  secret-manager references, and one-time GitHub installation state.
- Added immutable installation binding, forced PostgreSQL RLS for tenant
  control tables, serialized hash-linked administrative audit events, and a
  redacted tenant operational overview.
- Added a responsive read-only operator console with in-memory-only Bearer use,
  no mutation controls, `no-store` responses, and a restrictive content
  security policy.

### Security

- Tenant claims are used only as identity-configuration lookup hints; authority
  is granted only after RS256 signature, issuer, audience, expiry, tenant, and
  group verification.
- Bootstrap fallback is restricted to a verified `platform_admin` principal
  whose tenant claim is exactly `*`.
- Webhook secrets resolve from allowlisted `env://` references at request time;
  resolved values, references, installation state, and tokens are excluded
  from overview responses and structured operation events.

### Evidence boundary

- The hosted control plane is supervised and deployable, but it does not claim
  SCIM, SAML enrollment, managed KMS, HA, disaster recovery, SOC 2, or an SLA.

## 0.18.0 - 2026-07-19

### Added

- Added authenticated GitHub pull-request assurance with raw-body HMAC
  verification, immutable installation-to-tenant routing, durable delivery
  replay protection, and deterministic GitHub Check request contracts.
- Added offline RS256 OIDC verification against pinned JWKS, issuer, audience,
  expiry, not-before, tenant, groups, JTI replay, duplicate JSON member, and
  minimum RSA key-strength checks.
- Added the optional hosted adapter with PostgreSQL forced row-level security,
  transactional approval and Check outbox writes, freshness-bounded HTTPS JWKS
  rotation, short-lived GitHub App publication credentials, health/readiness
  routes, secret-free operation events, and a reference container.
- Added a PostgreSQL 17 integration workflow plus hostile hosted-adapter smoke
  and reverse-stub challenge receipts.

### Security

- Tenant identity is derived from immutable GitHub App installation mappings;
  caller-supplied tenant headers have no authority.
- Human decisions remain committed independently of GitHub availability, while
  failed publication remains classified in a bounded transactional outbox.
- Hosted network destinations require HTTPS, use five-second timeouts, and do
  not follow redirects.

### Evidence

- Enterprise PR assurance and the hosted adapter both reached ForgeLine grade A
  with strict SpecLine contracts, validator mutation gates, architecture gates,
  hostile tests, and non-hollow smoke checks.

## 0.17.3 - 2026-07-18

### Added

- Added `factory verify-receipts`, an offline Receipt v2 mutation gate that
  proves digest, signature, identity, and back-dated revocation failures with
  exact error codes and a canonical challenge receipt.
- Added property-based canonical JSON tests for stable round trips, dictionary
  ordering, Unicode, non-finite floats, lone surrogates, and unsupported values.
- Added an enforceable documentation contract and meaningful docstrings for
  every distributed public Python function and callable member.

### Security

- Added adversarial Studio mission-decision HTTP tests for wrong tokens,
  repository escapes, and replayed decisions without receipt replacement.
- Hardened migration receipt verification so malformed evidence rows and
  digests return structured invalid verdicts instead of unclassified errors.
- Added the receipt-chain mutation gate to the identity-pinned Sigstore CI path.

### CI

- Added Hypothesis to the standard development and release test dependency set.
- Updated Gradle Actions to `v6.2.0`, removing the deprecated Node 20 action
  runtime and the post-build Gradle cache-cleanup invocation.
- Updated the Marketplace workflow's immutable release default to `v0.17.3`;
  publication still requires the separately scoped JetBrains publisher token.

## 0.17.2 - 2026-07-18

### Added

- Added nine owner-supplied concept illustrations, an ordered SHA-256 asset
  manifest, and an accessible walkthrough for GitHub, PyPI, Product Hunt
  preparation, GitHub release assets, and the Zenodo source archive.
- Added deterministic publication tests for image identity, dimensions, order,
  alt text, absolute PyPI image URLs, and visual evidence boundaries.

### Fixed

- Aligned all public install instructions, IDE download links, and narrated
  quick-start asset names with the verified `0.17.1` release.
- Corrected Product Hunt instructions: gallery video entries require a full
  YouTube URL; a local MP4 is not a valid video entry.

### Evidence boundary

- The new artwork is labeled as concept illustration, not shipped UI or
  measured outcome evidence. The metric-bearing draft infographic is excluded.

## 0.17.1 - 2026-07-17

### Security

- Replaced the stored PyPI API-token publish path with GitHub OIDC Trusted
  Publishing and enabled distribution attestations.
- Added a release-workflow regression test that rejects stored PyPI
  credentials or removal of the protected environment and OIDC permission.
- Split validation from deployment so OIDC and release-write permissions exist
  only in the protected publish job.
- Added a pull-request package contract that builds, checks, installs, and
  exercises the wheel before release.

## 0.17.0 - 2026-07-17

### Added

- Runnable signed target packs for deterministic CLI, FastAPI, and local stdio
  MCP starters, alongside the existing worker, web, Expo, and agent UI targets.
- A 29-pack built-in catalog spanning targets, React/Next.js/Expo/browser
  extension surfaces, eight language families, seven common capabilities,
  data pipelines, evaluation harnesses, and admin operations.
- `factory pack compose` for compatible, hash-bound composition plans with no
  implicit generation, execution, deployment, or publication authority.
- Pack compatibility declarations for target support, required pack kinds,
  conflicts, and provided capabilities.

### Changed

- Capability Pack validation now rejects ten meaningful contract mutations,
  including generator drift, hollow validators/goldens, relaxed migration
  policy, and empty provided-capability declarations.
- Public architecture, Product Mission, pack, install, citation, and Zenodo
  metadata now describe the same 0.17.0 product surface.

### Compatibility

- Existing `local-split`, `split-hosting`, `expo-preview`, `eas-store`,
  `local-operator`, and `private-container-host` deployment profile IDs remain
  unchanged.
- Pack composition creates a review artifact only. Product-specific code still
  requires a Product Graph value slice, independent verification, and explicit
  release approval.

## 0.16.0 - 2026-07-17

- Added Product Graphs, value slices, bounded Missions, no-finish verification,
  evidence-linked PR drafts, classified outcomes, Meter v2, Studio product
  controls, IDE requirement proof links, and the first four signed target packs.
