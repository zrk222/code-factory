# Release Channels

Release workflows must bind artifacts to one source commit and pass the
candidate preflight. The preflight now requires strict architecture health and
release-cadence admission. A blocked preflight stops automated publication; it
does not change the state of an already published GitHub release or a manually
uploaded artifact.

Required publication checks are the currently configured protected-main CI and
channel-specific release gates. A scoped AI source review can inform the owner,
but it is not a required status check, independent human approval, or proof of
runtime safety. PyPI and Hugging Face environments do not require a second
human. Keep the release draft until applicable review, quality and publication
checks are satisfied.

The PR architecture job also runs `factory audit governance --base <base SHA>`.
It blocks edits to dated self-audit JSON and the explicit conflicting
second-human review rules that previously escaped review. Muse receipt
freshness, policy binding, tamper resistance and on-demand lifecycle are
checked by the adversarial plugin tests in CI. These checks are bounded and do
not turn a source merge into release approval.

| Channel | Artifact or surface | Release path | Success evidence |
| --- | --- | --- | --- |
| GitHub | Source tag, wheel, sdist, media and any editor packages included in the selected release mode | Dispatch `publish.yml` with an existing draft tag; its protected publisher attaches the verified bundle and publishes the release after PyPI | Public release URL and green workflow |
| PyPI | `factoryline-code-factory==0.50.0` | Trusted Publishing from `publish.yml` | PyPI project version and attestation |
| Official MCP Registry | `io.github.zrk222/code-factory` local stdio descriptor | Post-PyPI GitHub OIDC job in `publish.yml` | Public registry entry and green registry job |
| Hugging Face | Static Code Factory Space | Manually dispatch the `huggingface` environment workflow | Green Space workflow and public Space |
| Zenodo | Versioned source archive under concept DOI | GitHub release integration | Public version record; concept DOI remains stable |
| VS Code / Open VSX | `factoryline-vscode-1.3.6.vsix` candidate | Upload VS Code through the Microsoft Marketplace website; use the protected publisher workflow for Open VSX | Installable VSIX and public marketplace version |
| JetBrains | `factoryline-intellij-1.3.6.zip` candidate | Owner-authorized direct upload after required checks and live Marketplace validation; the protected publisher workflow remains available | Compatible ZIP plus an accepted Marketplace upload receipt; public availability still requires moderation |
| Devin | `code-factory-evidence` plugin 1.3.6 | Source-pinned contribution to `CognitionAI/devin-marketplace`, after live plugin tool acceptance | Accepted marketplace contribution and indexed entry; a submitted PR is pending review, not public availability |
| OpenCode | Native `code-factory-opencode` plugin 0.1.0 | Build a self-contained module and install under `.opencode/plugins/`; publish a registry package only after registry authentication and independent receipt | Project plugin loads and CF/ForgeLine lanes run or report exact limits |
| Product Hunt | Product page, gallery, and YouTube link | Signed-in maker editor | Public page visibly reflects the new copy/media |

### 0.50.0 / 1.3.6 release

- Core 0.50.0 is public on [GitHub](https://github.com/zrk222/code-factory/releases/tag/v0.50.0)
  and [PyPI](https://pypi.org/project/factoryline-code-factory/0.50.0/).
- The [Hugging Face Space](https://huggingface.co/spaces/zrk222/code-factory)
  and the [Zenodo archive](https://doi.org/10.5281/zenodo.24451994) are public.
- [VS Marketplace](https://marketplace.visualstudio.com/items?itemName=zrk222.factoryline-vscode)
  lists 1.3.6. JetBrains accepted the 1.3.6 submission for review.

The core release built and verified the wheel and source archive. The
[publication run](https://github.com/zrk222/code-factory/actions/runs/45093735087)
skipped editor builds and registry metadata publication. Editor uploads ran separately.

### Coverage and benchmark notes

Your AI writes the change. Code Factory shows what was actually checked.
Configured native security rules now span **12 languages**, with source-bound
traces, default/review tiers and explicit coverage gaps. Frozen JSON, SARIF
2.1.0, opt-in pre-commit and byte-exact mutation diffs fit existing team reviews.
Signed-observation claims, the bounded Proof Agent and the read-only Devin
plugin turn agent suggestions into inspectable evidence—not automatic approval.

Optional local-browser evidence now checks reviewed pixels, accessible control
identity, terminal UI state and one correlated API response. Prestige token
checks and mutation challenges are replayed against current source bytes.
Explicit fixture admission, pinned tools and cleanup evidence are required;
missing evidence remains incomplete. This is not native-device certification,
exhaustive accessibility testing or release approval. Topic-based evidence recall
also shares corpus preparation, preserving exact receipts and fresh trust checks;
its measured ranking gains are not a full-audit or detector-accuracy claim.

Final integration adds the foreground coordinator's signed fresh-worker handoff,
request replay and owned cleanup, corrects Gitleaks' native report version and
the JetBrains artifact path, and fixes browser CI compatibility without raising
quality limits. The newer advisory record separates CodeQL **15/91 analyzed**
from **70/161 not executed**, and pattern replay **6/161 exposed**. These are
not whole-CF blind recall or a replacement for the historical precision study.
[Lane-separated evidence](evidence/advisory-recall-factory-20261121.json).

Current coverage adds Go/Java/C#/Ruby framework sources and sinks plus wider
Ruby/Swift trust checks. New request rules are review-tier; the shipped variant
has no fresh precision score. Round 7 below is the earlier ruleset.
[Coverage evidence](evidence/polyglot-coverage-round8.json).

Historical Round 7 supported **38/40 decided default-tier alerts = 95.0%**
(Wilson 95% **83.5–98.6%**), with **12 additional unclear**. Review tier supported
**23/40 = 57.5%**, with 3 unclear; advisory recall was **0/161**. Six languages
had insufficient precision samples. AI review labels are not independent human
validation or twelve-language accuracy. The earlier Round 6 54/60 (90%) panel
is a separate study; do not present the different sampling designs as a measured
improvement. [Per-language evidence](evidence/polyglot-readiness-round7.json).
SDK imports, strict complexity failures, duplicated implementation files and
unsafe/unbounded receipt reads were repaired without raising architecture caps.
No repeatable scan-speed gain is claimed.

Each channel must retain these bounds when using the shorter value-led copy.
Prepared artifacts, uploads, moderation and public availability remain distinct.

### Launch measurement procedure

Capture raw distribution signals before interpreting them. The helper saves
PyPI and, when authenticated through `gh`, GitHub traffic responses in one JSON
receipt. It does not calculate users, conversion, or savings.

```powershell
.\scripts\capture_launch_metrics.ps1 `
  -Campaign "linkedin-launch" `
  -PostUrl "https://www.linkedin.com/posts/..."
```

The output goes to `.factory/launch-metrics/` and records the observation time,
raw sources, and any unavailable source errors. Run it before posting, on the
next day, and after material discussions or posts. Compare dated observations;
do not describe PyPI downloads as unique humans or attribute them to a campaign
without a separate source.

### Previous JetBrains 1.3.3 candidate

JetBrains 1.3.3 contains the saved-VFS consistency and background Studio startup
patch and is present in the Marketplace listing. A live read-back reported
“Problems configuration invalid” because the plugin archive cannot be extracted,
while five IDE verification rows showed Compatible. The plugin uses the
separately configured local CLI.
Core 0.49.5 and editor 1.3.2 records below are historical and remain unchanged;
this JetBrains-only patch does not bump VS Code, core, Hugging Face or PyPI.

### November 2026 candidate preflight

The candidate set is core 0.49.6, VS Code/Open VSX 1.3.3 and JetBrains 1.3.4.
Metadata is prepared only; no artifact has been built or published from this
checkout. The live JetBrains listing for 1.3.3 reports “The plugin archive file
cannot be extracted,” despite five IDE compatibility rows showing Compatible.
Build 1.3.4 as a fresh ZIP and require CRC/full extraction reads, unique archive
paths, a unique plugin manifest and `guardianReleaseGate` before any upload. Do
not reuse the 1.3.3 archive.

### Editor marketplace snapshot

Release-grade test evidence must come from the protected-main
`signed-receipts.yml` runner. It records the source commit, environment,
dependency versions, exact commands, logs and JUnit digest; any tracked source
change during checks aborts receipt creation.
Each check runs on a separate fresh Actions runner, preventing a test process
from modifying the source inspected by another lane. The aggregation runner
validates each check's GitHub job/step result, source identity and artifact
digests before combining its results. Test/scanner runners have no signing
permissions; only the separate attestor signs, and it never executes repository
code or installs the candidate package.
Publishers verify GitHub artifact
attestation against that exact commit, workflow and main ref, rejecting
self-hosted runners. Local checks are development evidence and cannot replace
this receipt. Attestation establishes provenance, not software correctness.

The public seeded Python AST benchmark runs in `audit-benchmark.yml`. Its eight
hand-labeled cases previously yielded 2 true positives, 2 true negatives, 0 false
positives and 4 false negatives: precision 100%, recall 33.3%. The receipt now
reports test-oracle strength separately: 0/3 hollow-test cases detected
(recall 0%, 95% Wilson interval 0–56.1%); tenant-isolation remains 0/1
(recall 0%). These are measured misses, not implied coverage. This small,
public corpus is not independent holdout or production evidence; the workflow
preserves measurements rather than approving a release. Mutation testing has
a separate manual workflow; configuring it is not a measured mutation-survival
result. The candidate detection fixes now yield 6 true positives, 2 true
negatives, and no false positives or false negatives in local replay of the
unchanged corpus. The same explicit `db.get` tenant-read contract is applied
to every defective, repaired, and clean input. This is development regression
evidence; independent held-out accuracy, runtime tenant isolation, and current
CI provenance remain separate requirements.

Provider read-back on 2026-10-04:

| Listing | Published version | Provider-reported downloads | Other provider metric |
| --- | --- | ---: | ---: |
| [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=zrk222.factoryline-vscode) | 1.0.2 | 395 downloads | 3 installs |
| [Open VSX](https://open-vsx.org/extension/zrk222/factoryline-vscode) | 0.9.9 | 4,720 downloads | 0 reviews |

These are channel counters, not unique users. VS Code 1.0.2 was published on
2026-10-01; the publisher page read on Oct 4 showed it updated three days ago.
Open VSX still reports 0.9.9. The 1.1.0 artifacts in that candidate were not yet
published.

The release pipeline never treats a queued review, draft listing, uploaded
artifact, or workflow dispatch as a completed publication. Each channel is
reported as published, pending review, blocked, or not configured. Direct
marketplace uploads require their own provider acceptance and approval evidence.

Core 0.50.0 and editor 1.3.6 artifacts must bind to one final source commit.
Version metadata does not establish provider availability. The latest owner
provider read-back recorded here, 2026-10-31, verified core 0.49.0, VS Code 1.3.0
and JetBrains 1.3.1; update each channel only from its own publication receipt.
Do not describe metadata preparation, an upload or a review queue as publication.
Release preflight must pass strict architecture health, prospective cadence,
source review, and protected provider gates before publication. Do not weaken
or skip release preflight to force a provider upload.

The release-train cap took effect at `2026-09-21T15:01:54Z`, the recorded
commit time when the policy was added. Core admission reads `v*` tags and
published GitHub timestamps. Adapter preflight reads its own immutable
`vscode-v*` or `jetbrains-v*` tags and checks the corresponding editor version;
a core release cannot be counted as an editor release. Each channel retains
the 4-per-30-day limit and 7-day interval. The publish
workflow dispatches only from protected `main`, accepts only an existing draft
release, validates the immutable tag, waits at the protected `pypi` environment,
and marks the GitHub release public only after the approved PyPI publication
succeeds. Set `core_only=true` when uploading the editors independently. The
workflow builds and checks fresh Python distributions and excludes editor
validation and editor assets. Microsoft and JetBrains website uploads keep
their own package and provider checks.

Cadence exceptions are disabled after the completed publication of the
previously approved candidates. No automatic or routine exception path is
available for a later release; the 4-per-30-day cap and 7-day minimum remain in
force. Historical exception receipts and already published tags/artifacts are
retained as immutable records; this policy does not change their status.

The owner explicitly approved one additional version-bound exception on
2026-11-21: core 0.50.0 and VS Code/Open VSX/JetBrains 1.3.6 only. It requires
owner dispatch, an explicit version opt-in, exact source/tag/environment/run
bindings and an expiring receipt. The general exception switch stays disabled;
tests, provenance, architecture and publication gates remain mandatory.

### 0.46.0 core agent handoff evidence under Code Factory authority

This release imports explicit agent handoff structure as evidence: typed acyclic
stages, scoped source preconditions, real before/after artifacts, provider-
declared tool and checkpoint hashes, and resume lineage. Code Factory binds
those facts to the current Oracle Contract and rejects drift. The adapter and
its local Proof Worklog are deliberately read-only: they do not run a provider,
execute commands, post to a tracker, inherit agent authority, or make approval,
merge, publication, or deployment decisions.

### 0.45.0 SaaS Reality and unified proof operations

This release adds provider-neutral OAuth/OIDC identity-to-entitlement proof and
unifies Proof Review, RevenueForge, AppForge design contracts, Evidence Memory,
enterprise operations, deterministic policy compilation, Codex metadata
integrity, Graph Ops, MCP, WebMCP, and IDE adapters. Unknown evidence remains
blocked; private provider implementations are not included.

### 0.44.3 Journey proof and audited healing

This release adds Journey Reality, bounded failure capsules, and stateful
workflow proof. Proof-gated healing can remain human-controlled or run in a
supervised automatic mode, but a candidate is accepted only when its positive
proof passes, its negative control fails, and the repairing agent's work passes
an independent audit. Unknown evidence stays unknown. BYOK/local remains the
default, and neither mode grants approval, merge, release, or credential
authority.

### 0.44.2 Intent lineage navigation

This patch makes a verified Forge intent trace easier to inspect in Graph Ops.
Bound adapters now show a compact trace-to-source path and a local **Inspect
source** navigation action that focuses the exact hash-bound Forge ship line.
Missing, malformed, and mismatched bindings keep the source action withheld.
The change remains read-only: it does not run, repair, approve, publish,
deploy, sign, message, or access credentials.

### 0.44.1 Current visuals and transparent outcome model

This patch aligns the public Code Factory surfaces with the current product,
adds role-specific expected outcomes, and publishes one clearly bounded 60-day
personal-use case. Observed activity and modeled capacity remain visually and
textually separated; the case is not a benchmark, guaranteed ROI, or verified
cash saving.

### 0.44.0 First Proof

This adoption release adds a sealed, one-command hollow-test demonstration,
privacy-safe and tamper-evident Proof Cards, and local opt-in activation
milestones with no central telemetry. A 21-day feature pause concentrates work
on reliability and activation; a voluntary Proof Clinic invites ten real
repositories without pre-claiming participants or outcomes.

### 0.43.0 Evidence Supply Line

This release adds an admitted wrapper for any local agent CLI, explicit
independent-validator execution, exact workspace-delta receipts, and immutable
Agent License ingestion. It also adds inert Gauntlet drafts derived from real
repository structure and bounded Claude Code hook traces. The wrapper observes
but does not sandbox the process; drafts cannot execute before human-reviewed
promotion and a separate named admission.

### 0.40.2 MCP Registry metadata hotfix

This hotfix shortens the public MCP descriptor to the registry's declared
description limit. It does not change the local MCP tool surface, runtime
authority, IDE Health observations, or Index Continuity classifications.

### 0.40.1 IDE Health and Index Continuity

The current release adds bounded local JetBrains IDE Health observations and an
explicit Index Continuity baseline/compare path. Runtime samples remain in
memory, while the optional structural baseline stays inside the workspace.
Neither control changes configuration, repairs an index, assigns a root cause,
or predicts a performance result.

### 0.40.0 Intake Grill, Proof-Delta Loop, and Gauntlet

The current release adds source-bound framework, intent, acceptance-evidence,
and external-effects decisions before an optionally intake-required Product
Mission can start. It also blocks a mission retry unless the packet binds a
changed candidate diff and new hash-checked evidence to the latest failed
criterion. Finally, Gauntlet turns a human-written, named set of local E2E
sabotage cases into an expiry-bound, one-run supervised batch and an
offline-verifiable Survival Card. The local MCP and Graph Ops surfaces inspect
these receipts; neither can make decisions or execute work. A Survival Card is
not a production-readiness, security, coverage, performance, cost, token,
quality, or release claim.

### 0.39.1 Official MCP Registry

The Official MCP Registry descriptor makes the existing local, read-only
MCP server discoverable using the public PyPI/`uvx` package entry. It publishes
only after the exact package version and ownership marker are visible from
PyPI. It neither hosts the server nor grants write authority.

### 0.39.0 LangGraph Assurance Bridge

`factory langgraph replay-verify` compares a supplied sealed reference lineage
with a separately recorded resumed lineage. It returns resume parity only when
the supplied transitions match and neither lineage exposes deterministic stale
state, duplicate completed effects, or unsafe parallel writes. A divergence
produces a hash-only incident capsule with Mermaid and a review-only recovery
cone. The open-source bridge also exposes a read-only MCP tool and an opt-in
GitHub Action that writes the same Proof Card from pre-recorded receipts. It
does not invoke LangGraph, mutate checkpoints, replay effects, establish
production resilience, or estimate savings.

On August 31, 2026, the public Marketplace API reported 0.8.20 approved and
listed, no unapproved binary update, and an open upload slot. Listing metadata
was still pending review. The prepared 0.9.0 successor must pass the live
binary-slot gate again in the protected publication workflow.

### 0.42.0 Declared Change Profile and Senior Attention

This release adds a hash-bound, human-declared Change Profile to the existing
independently human-promoted Judgment Capsules and deterministic, read-only Change
Safety Case. It can route novel declared boundaries to Senior Attention without
inspecting source semantics; it cannot infer intent, promote/waive a decision,
run evidence, repair code, approve, merge, publish, deploy, sign, message, or
access credentials.

### 0.8.19 Guardian Core + Engineering Judgment candidate

The JetBrains-only candidate adds bounded local Guardian Core observations plus
the conventional Change Profile handoff for selected Change Lists. It shows
declared attention and decision drift without changing IDE configuration,
running a CLI command outside confirmed actions, or applying a repair.

### 0.41.0 Engineering Judgment Safety Case

The prior release added repository-tracked, independently human-promoted Judgment
Capsules plus a deterministic, read-only Change Safety Case for explicit changed
paths and hash-bound proof receipts. The route is review context only; it cannot
infer intent, promote/waive a decision, run evidence, repair code, approve,
merge, publish, deploy, sign, message, or access credentials.

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
