# Code Factory 0.46.4 — Proof-Coupled Agent Handoffs

Code Factory 0.46.4 makes the review story easier to understand while keeping
the authority boundary hard. This is a patch release for the additive Junie
handoff work and the public explanation of workflow performance.

6 mandatory audit lanes. 136 coded rejection conditions. One human-owned release decision.
The source inventory remains **81 lane-specific and 55 cross-cutting**
conditions; a project executes only the checks its approved
scope and configured runners can support.

## What changed

- **A faster review path, explained honestly.** Content-addressed receipts and
  dependency-aware `RUN` / `REUSE` / `SKIP` / `BLOCK` routing avoid repeating
  unchanged discovery and review archaeology. This reduces workflow overhead;
  it is not a claim about application runtime speed or guaranteed productivity.
- **Junie can get credit without becoming the oracle.** The MCP taxonomy and
  `factory junie-contribution` card bind a known tool, exact changed paths,
  per-file rationale, workspace-local SHA-256 hashes, explicit unknowns, and a
  visible credit line to the current taxonomy digest. Wrong tools, mismatched
  digests, unsupported paths, and unverified claims fail closed.
- **The IDE story stays optional.** FactoryLine for JetBrains 0.9.4 surfaces
  the same evidence beside Junie, Qodana, Copilot, or another analyzer. It is
  an independent proof layer, not a Junie dependency or endorsement.

## Release identity

| Surface | Version or tag |
| --- | --- |
| Code Factory core | `0.46.4` / `v0.46.4` |
| FactoryLine for JetBrains | `0.9.4` / `jetbrains-v0.9.4` |
| FactoryLine for VS Code | `0.9.6` / `factoryline-vscode-0.9.6.vsix` |
| Open VSX | `0.9.6` (published only after its protected workflow succeeds) |

## Boundaries

The package is local-first and read-only at provider boundaries. It does not
execute Junie or another agent, upload source, collect telemetry, approve,
merge, publish, deploy, sign, or receive credentials. A green local receipt is
evidence for the supplied inputs and checks, not a provider approval or a
production-readiness certification.

## Verification

The release workflow runs the repository test suite, package build and Twine
checks, clean-wheel smoke, VS Code tests/package validation, JetBrains Gradle
checks, and the signed release preflight before publishing. Provider workflows
remain separate and report their own accepted, pending, or blocked state.
