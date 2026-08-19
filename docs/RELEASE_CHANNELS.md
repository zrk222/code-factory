# Release Channels

Code Factory v0.38.0 publishes one verified source state through channel-specific
adapters. A successful GitHub release is not evidence that every moderated
listing has accepted the artifact.

| Channel | Artifact or surface | Release path | Success evidence |
| --- | --- | --- | --- |
| GitHub | Source tag, wheel, sdist, VSIX, JetBrains ZIP, media | Publish `v0.38.0`; `publish.yml` attaches the verified bundle | Public release URL and green workflow |
| PyPI | `factoryline-code-factory==0.38.0` | Trusted Publishing from `publish.yml` | PyPI project version and attestation |
| Hugging Face | Static Code Factory Space | Push `deploy/huggingface/` to `main` | Green Space workflow and public Space |
| Zenodo | Versioned source archive under concept DOI | GitHub release integration | Public version record; concept DOI remains stable |
| VS Code | `factoryline-vscode-0.8.10.vsix` | GitHub release bundle; protected `vscode-marketplace.yml` publishes an immutable, verified VSIX when its scoped publisher credential is configured | Installable VSIX or public Marketplace version |
| JetBrains | `factoryline-intellij-0.8.10.zip` | Scoped workflow update to public plugin 33009 after the existing pending metadata review clears | Installable ZIP or public plugin/version page after moderation |
| Product Hunt | Product page, gallery, and YouTube link | Signed-in maker editor | Public page visibly reflects the new copy/media |

The release pipeline never treats a queued review, draft listing, uploaded
artifact, or workflow dispatch as a completed publication. Each channel is
reported as published, pending review, blocked, or not configured.

JetBrains Marketplace publication remains blocked while any submitted update is
pending Marketplace approval. Do not dispatch the 0.8.10 candidate until the
Marketplace status gate reports clear.

### Visual Studio Marketplace publisher setup

The package is already bound to publisher `zrk222` and extension name
`factoryline-vscode`. To enable the separately protected marketplace lane:

1. Sign in to the Visual Studio Marketplace publisher portal with the account
   that owns `zrk222`.
2. Create a publisher credential with only **Marketplace (Manage)** scope and
   a bounded expiry. Store it as the `VSCE_PAT` secret in the GitHub Actions
   environment named `vscode-marketplace`; never put it in source, a release
   asset, or a repository-level secret.
3. Create or protect the `vscode-marketplace` environment with the repository's
   normal release reviewers.
4. Dispatch **Publish VS Code Marketplace extension** for the immutable
   release tag, first with `publish=false`. After the green candidate receipt
   is reviewed, dispatch it again with `publish=true`.

The workflow verifies the tag-to-commit binding, restores from the lockfile,
runs the high-severity audit and tests, seals the VSIX SHA-256, and verifies
the sealed artifact again before it can call the Marketplace. `vsce` receives
the environment-scoped `VSCE_PAT` only in the protected publication job. A
missing credential fails closed at the publish boundary. Replace this PAT path
with the Marketplace's supported Microsoft Entra automation path before the
December 1, 2026 global PAT retirement.

### 0.36.0 Graph Portfolio and Run Admission

`factory graph portfolio` derives a deterministic structural critical path,
safe proposal-only parallel waves, shared-proof candidates, and explicit
blocker chains from local Graph Ops evidence. `factory admission prepare|verify`
seals and rechecks a short-lived external-run proposal against a Loop Passport,
workspace, graph, budget, paths, approvals, and validity deadline. Graph Ops
renders the status while execution and external-harness authorization remain
disabled. This is not an autonomous runner and does not create a savings claim.

### 0.34.0 Merge Evidence Dossier and Proof Observatory

`factory proofsearch frontier plan|verify` creates and validates a sealed,
non-executing next-evidence plan. It ranks only user-supplied hypotheses by
declared repair-pair separation. Graph Ops renders the decision and keeps
experimentation, workspace changes, approval, merging, publishing, and
deployment locked. No saving or productivity value is inferred.

### 0.32.0 Graph Forensics and ProofSearch

`factory graph forensics` identifies the first semantic divergence and its
causal path from sealed lineage. `factory proofsearch` binds the resulting
proof slice to 2 through 12 supplied candidates, rejects hollow or unsafe
repairs, and selects one deterministic verified winner. Graph Ops displays the
complete Counterfactual Arena while apply, merge, publication, and deployment
remain locked. Paired observations are required for any savings value.

### 0.31.0 E2E proof and Team Pilot readiness

`factory e2e verify` proves an approved positive/negative command pair can
reject the declared failure instead of merely turning green. `factory team-pilot
readiness` hash-binds the five non-secret operating decisions required for a
human-selected, customer-managed reference review. Neither command accepts a
customer, provisions access, collects payment, or claims a managed service.

### 0.30.0 plan-to-proof and design review

`factory plan verify` turns a human-approved agent plan into a strict local
review contract. It compares exact plan paths and declared tests with a changed
diff, routes deep work to a named reviewer, and writes explicit Proof Debt for
human triage. The optional GitHub workflow publishes one neutral, commit-bound
advisory Check; it does not approve, merge, execute tests, invoke a provider,
or turn a plan into authorization.

The optional Prestige Design Review lane adds a purpose-led design brief and
visible review artifacts for hierarchy, responsive behavior, affordances,
consistency, and declared design tokens. It is evidence for a reviewer, not a
conversion claim, an accessibility certification, or a production-readiness
claim.

### 0.29.0 review-stack compatibility

The bundled VS Code and JetBrains adapter copy now explains the optional GitHub
Proof Review workflow. The workflow can coexist with CodeRabbit or another AI
reviewer without a vendor credential or comment becoming proof. The local
extensions remain local-first and do not gain approval, merge, source-write, or
model authority.

### 0.28.0 product surfaces

Proof Review, Verified Repair Sandbox, and Workspace Load Advisor are available
in the JetBrains adapter. They produce bounded local review packets and never
edit code, invoke a model, access credentials, or certify runtime isolation.

### Verifier Plane (0.27.0)

The Verifier Plane is release-visible but not a release authority. Its receipts
prove supplied local byte bindings, declared independent identities, and
deterministic checks. Runtime isolation, egress policy, and credential handling
remain separately evidenced by an external supervised runner.

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
