# FactoryLine for VS Code

Run a bounded FactoryLine command and inspect the local JSON receipt without
leaving VS Code. The extension never uploads your workspace, code, or receipts.

**Generate a local MVP, then catch hollow tests before review.** Keep the
receipts and proof path next to the code, then open **Graph Ops** to see what is
evidenced, blocked, or next. Start with **FactoryLine: Open Local Factory
Studio** or run `factory mvp "Build an approval tracker" --root .`. The
extension never calls a starter production-ready by itself.

## Commands

- **FactoryLine: Run Spec-to-Ship Assembly** runs `factory assemble <feature> --root <workspace>`.
- **FactoryLine: Continue Assembly to Next Boundary** runs the state-aware
  `factory continue [feature] --root <workspace>` workflow.
- **FactoryLine: Verify Feature Receipts** runs `factory verify <feature> --root <workspace>`.
- **FactoryLine: Open Local Meter** reads `factory meter --root <workspace> --json` after workspace confirmation.
- **FactoryLine: Open Latest Receipt** finds JSON under `.factory/` and `receipts/`, then renders a local receipt panel.
- **FactoryLine: Open Local Factory Studio** opens the confirmed loopback target compiler.
- **FactoryLine: Open Product Missions** opens Studio in deterministic PRD-to-mission mode.
- **FactoryLine: Open Unified Graph Ops** opens the bounded, read-only local evidence map.
- **Verifier Plane (terminal workflow)** runs `factory verifier session|verify|progress`
  to bind independent worker/verifier evidence, deterministic checks, and hard
  budgets. It validates supplied receipts; it does not execute or sandbox a runner.
- **PRD Grill (terminal workflow)** runs `factory prd grill PRD.md --root <workspace>`
  to create a capped, source-bound clarification sheet before PRD optimization
  or compilation. It never rewrites the PRD or starts a build.
- Requirement IDs such as `REQ-*`, `FR-*`, and `NFR-*` receive a read-only
  CodeLens that opens matching local proof in `.factory`, `receipts`,
  `coverage`, `tests`, or `specs`.

Each command requires a trusted VS Code workspace. FactoryLine accepts only a
feature name containing letters, digits, hyphens, and underscores; it does not
pass arbitrary shell fragments to your terminal.

For a GitHub pull request, the optional
[`factory github proof-review`](../../docs/GITHUB_PROOF_REVIEW.md) workflow
can publish the same deterministic proof facts beside CodeRabbit or another AI
reviewer. It does not require their account, import their comments as proof,
auto-approve, merge, or modify source.

For a team-operated agent change, run the CLI’s
[`factory plan verify`](../../docs/PLAN_TO_PROOF_REVIEW.md) in the trusted
workspace and attach the optional local JSON/Markdown/Mermaid packet to the
review. It makes approved scope alignment and Proof Debt visible; it does not
add an autonomous extension action, execute tests, approve, merge, or modify
source. See the [Teams and Enterprise Operations Manual](../../docs/ENTERPRISE_TEAMS_OPERATIONS.md)
for role boundaries and rollout.

For UI-scoped work, add the optional [Prestige Design Review](../../docs/PRESTIGE_DESIGN.md)
to the same local evidence path. It supplies a purpose-led design brief and
review artifacts for hierarchy, responsive behavior, affordances, consistency,
and design tokens. The extension does not apply a design change or treat a
visual score as production readiness.

## Install

Install the Code Factory CLI first:

```powershell
pip install factoryline-code-factory
```

Build a local VSIX from this directory, then install it in VS Code:

```powershell
npm ci
npm run package
code --install-extension factoryline-vscode-0.8.9.vsix
```

Set `factoryline.command` if the `factory` executable is not on VS Code's PATH.
Product Missions create only supervised, approval-required local packets and do
not grant execute, merge, deploy, publish, connector, credential, or messaging authority.
Requirement CodeLens navigation reads bounded local text artifacts only; it does
not run FactoryLine or change approval state.

If this free, local-first workflow helps, use the post-success **Star Code Factory** action or visit [the GitHub repository](https://github.com/zrk222/code-factory).
That action is optional, opens only GitHub when selected, and sends no workspace data.

Code Factory 0.20 also includes an optional hosted GitHub PR-assurance adapter,
durable mission graphs, and secret-free BYOK policies. VS Code workspaces use
those controls through the local `factory` CLI or loopback Studio; the
extension never stores provider keys.
It is deployed separately from this local editor extension; see
[Hosted PR assurance](../../docs/HOSTED_PR_ASSURANCE.md).

## Scope

This is the VS Code adapter. The separate JetBrains Platform adapter and its
compatibility boundary are documented in [docs/INTELLIJ.md](../../docs/INTELLIJ.md).

### Verifier Plane (0.28.0)

`factory verifier` separates a worker's candidate receipt from a distinct
verifier's evidence. It rejects self-verification, drift, path escape, false
passing checks, and declared budget overrun. Graph Ops renders a bound session
as `runtime-unattested` until independently supplied evidence is verified;
this adapter does not claim to execute or enforce a sandbox.

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
