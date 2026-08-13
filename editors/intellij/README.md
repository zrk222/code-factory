# FactoryLine for JetBrains IDEs

FactoryLine for JetBrains IDEs keeps the local proof loop next to the project. It
runs an explicit FactoryLine command, then displays the command result and the
newest local JSON receipt in a tool window.

**Generate a local MVP, then catch hollow tests before review.** Inspect the
proof path in the IDE, then open **Graph Ops** to see the next evidence gap.
Start with **Tools > FactoryLine > Run First Proof**, then run
`factory mvp "Build an approval tracker" --root .`. A starter remains a
starting state until product-specific proof exists.

## What It Does

- `FactoryLine: Run Spec-to-Ship Assembly` runs `factory assemble <feature> --root <project>`.
- `FactoryLine: Continue Assembly to Next Boundary` resumes safe local stages
  with `factory continue <feature> --root <project>`.
- `FactoryLine: Verify Feature Receipts` runs `factory verify <feature> --root <project>`.
- `FactoryLine: Open Local Meter` runs `factory meter --root <project> --json` after workspace confirmation.
- `FactoryLine: Analyze Changed Proof` runs `factory risk-diff --root <project> --json`.
- `FactoryLine: Analyze Workspace Load and Remote/WSL Preflight` runs `factory workspace inspect --root <project> --json`, measures only bounded local filesystem/path facts, and offers manual review paths. It never changes heap, caches, indexes, inspections, plugins, project files, credentials, or remote settings, and it is not an IDE performance diagnosis.
- `Workspace Advisor: Save local report` explicitly writes JSON, Markdown, and Mermaid under `.factory/workspace-advice`; MCP inspection never writes those artifacts.
- `FactoryLine: Review Current Diff` runs `factory change review --root <project> --json` and shows an attention-first, structured local review of the branch delta, staged changes, unstaged changes, and non-ignored untracked files.
- `FactoryLine: Review This File` runs the same analysis with an explicit active-editor path, so a developer can exclude unrelated local work from the review scope.
- `FactoryLine: Save Review Handoff` writes the exact review JSON, Markdown, and Mermaid map below `.factory/change-reviews/` only after a second workspace confirmation. It is a local handoff packet, not an approval or an automatic repair.
- `FactoryLine: Prepare Verified Repair Sandbox` selects one native Change List, seals its exact project paths and measured bytes in a local Scope Passport, then permits an explicit textual candidate-patch check. It never calls an AI runner, estimates token/credit savings, applies a patch, runs a test, or commits.
- The Repair Sandbox can copy its current local proof context for a manual AI Chat paste, plus a local stdio MCP configuration. Neither action configures AI, uploads source, consumes AI credits, or grants execution authority.
- `FactoryLine: Open Latest Receipt` shows the newest JSON receipt below `.factory/` or `receipts/`.
- `FactoryLine: Check Latest Receipt Signature State` runs `factory receipt status` on that receipt. It reports signature presence or `UNSIGNED`; it does not claim signer identity.
- `FactoryLine: Open Local Factory Studio` opens the confirmed loopback target compiler.
- `FactoryLine: Open Product Missions` opens Studio in deterministic PRD-to-mission mode.
- `FactoryLine: Open Unified Graph Ops` opens the bounded, read-only local evidence map.
- **Verifier Plane (terminal workflow)** runs `factory verifier session|verify|progress`
  to bind a worker receipt to distinct verifier evidence, deterministic checks,
  and hard budgets. The CLI validates supplied evidence; it does not run or
  sandbox the external verifier.
- **PRD Grill (terminal workflow)** runs `factory prd grill PRD.md --root <project>`
  to write a capped, source-bound clarification sheet before PRD optimization
  or compilation. It never modifies the PRD or authorizes implementation.
- `FactoryLine: Mission Graph & Provider Operations` initializes and inspects
  durable graphs, verifies receipt chains, exports Mermaid, records guarded
  events, and routes a JetBrains-selected secret-free BYOK policy.
- `REQ-*`, `FR-*`, and `NFR-*` references receive a read-only gutter link to
  matching local proof under `.factory`, `receipts`, `coverage`, `tests`, or `specs`.

## Safety Boundary

The adapter runs a command only after a feature-name prompt and explicit local-workspace confirmation.
It invokes the configured executable directly through IntelliJ's process API:
it does not start a shell, construct command strings, upload source code, send
receipts over the network, or certify a release by itself.

The receipt viewer is deliberately fail-closed: a readable receipt is marked
**unassessed** until an explicit verification path establishes the claim. The
adapter never silently signs a receipt, applies an override, or converts an
untrusted/missing receipt into a green state.

Proof Review is deliberately conservative: it displays CLI facts, orders the
most urgent findings first, opens only changed files that remain inside the
project, and can copy a concise handoff brief. It never edits code, runs a
test, commits, publishes, deploys, accesses credentials, or sends project data
over the network. A future repair flow must create an isolated candidate and
pass independent checks before a human chooses whether to apply it.

For a GitHub pull request, the same local proof facts can appear beside
CodeRabbit or another AI reviewer through the optional
[`factory github proof-review`](../../docs/GITHUB_PROOF_REVIEW.md) workflow.
It is complementary: FactoryLine does not require a vendor account, ingest AI
comments, auto-approve, merge, or treat a suggestion as verification evidence.

Verified Repair Sandbox is that first professional repair-control surface: it
keeps a candidate's declared Git patch paths inside one native Change List,
blocks stale scope bytes, and leaves a local JSON/Markdown/Mermaid handoff for
the developer and independent verifier. It does not claim that scope control
proves a patch correct, nor does it call or configure a repair model. See
[`docs/REPAIR_SANDBOX.md`](../../docs/REPAIR_SANDBOX.md).

Workspace Load Advisor is the parallel performance-and-remote **observation**
surface. It makes project shape visible before a developer manually changes
JetBrains project exclusions or evaluates a remote/WSL path setup. It measures
neither IDE runtime behavior nor performance improvement and cannot apply a
configuration change. See [`docs/WORKSPACE_ADVISOR.md`](../../docs/WORKSPACE_ADVISOR.md).

## Install

1. Install `factoryline-code-factory==0.29.0` into the Python environment that
   IntelliJ inherits.
2. In your JetBrains IDE, open **Settings > Plugins > Marketplace**, search for
   **FactoryLine**, and install the
   [official listing](https://plugins.jetbrains.com/plugin/33009-factoryline).
3. Restart the IDE, then use the **Tools > FactoryLine** menu or the
   **FactoryLine** tool window.

For an offline installation, download a verified plugin ZIP from a matching
FactoryLine release and use **Install Plugin from Disk...**.

Set an absolute executable path under **Settings > Tools > FactoryLine** only
when `factory` is not already discoverable on IntelliJ's PATH.
Product Missions create only supervised, approval-required local packets and do
not grant execute, merge, deploy, publish, connector, credential, or messaging authority.
The gutter navigator reads bounded local evidence only and never executes a
mission or changes an approval.

After a successful local proof or assembly command, FactoryLine may offer an
optional **Star Code Factory** action once per installed plugin version. It only
opens the repository when you select it and shares no workspace data.

## Local Development

```powershell
.\gradlew.bat check buildPlugin verifyPlugin
```

The output ZIP is written to `build/distributions/`. `runIde` opens a sandboxed
IntelliJ instance for manual inspection.

## Scope

This is a JetBrains Platform plugin, with only the shared
`com.intellij.modules.platform` dependency. CI verifies its ZIP against
IntelliJ IDEA, PyCharm, WebStorm, Rider, CLion, GoLand, RustRover, and
DataGrip builds from the 2025.2 baseline forward. The CI matrix verifies
current stable builds, including an explicit DataGrip archive because archived
2025.2 installers are not available through the verifier resolver.

Code Factory 0.20 also includes an optional hosted GitHub PR-assurance adapter,
a durable mission graph, and a secret-free multi-provider route selector.
It is deployed separately from this local IDE plugin; see
[Hosted PR assurance](../../docs/HOSTED_PR_ASSURANCE.md).

`marketplacePreflight` inspects the actual ZIP and fails when its descriptor,
light/dark plugin logos, vendor contact, project URL, or release notes are
missing. GitHub releases remain the current installation channel. The initial
Marketplace upload requires a human Vendor profile and review; after that
bootstrap, the scoped GitHub workflow publishes verified updates using a
Marketplace publisher token. See [the Marketplace runbook](../../docs/JETBRAINS_MARKETPLACE.md).

### 0.28.0 control surfaces

Proof Review, Verified Repair Sandbox, and Workspace Load Advisor are local,
review-first controls. They produce bounded handoffs and do not edit code,
call a model, apply a patch, or claim IDE performance or runtime isolation.

### Verifier Plane (0.27.0)

`factory verifier` keeps the worker and verifier identities distinct, locks the
verifier bundle and evidence to SHA-256 receipts, and halts deterministic
no-progress loops for owner review. Unified Graph Ops exposes those sessions as
read-only `runtime-unattested` state until independently supplied evidence is
verified. The plugin never claims to provide a runtime sandbox.

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
