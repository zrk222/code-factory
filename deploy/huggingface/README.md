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
  - mcp
  - model-context-protocol
  - cursor
  - opencode
  - local-first
pinned: false
license: apache-2.0
short_description: Build a local MVP. Catch hollow tests before review.
---

# Code Factory

This is the browser preview for
[Code Factory](https://github.com/zrk222/code-factory), an open-source,
local-first proof layer for AI-assisted code.

**Generate a local MVP, then catch hollow tests before review.** Start from a
plain-language outcome, a fuzzy PRD, or a risky diff. Code Factory keeps the
proof path visible and does not call a starter production-ready before relevant
evidence exists.

The canonical Python package is
[`factoryline-code-factory`](https://pypi.org/project/factoryline-code-factory/).
Release `v0.28.2` is archived under the repository's stable Zenodo concept DOI at
[Zenodo](https://doi.org/10.5281/zenodo.21381405).

Use the same local proof context from Cursor or OpenCode through the documented
[MCP connection](https://github.com/zrk222/code-factory/blob/main/docs/AI_CLIENTS.md).
The client connection is local and read-only; it does not upload source or
grant provider, credential, deployment, or publishing authority.

Before a PRD becomes a scaffold, run `factory prd grill PRD.md --root .` for a
capped, source-bound clarification sheet with recommendations and answer stubs.
It never rewrites the PRD, invents answers, calls a model, or authorizes a
build. Read the full [PRD Grill guide](https://github.com/zrk222/code-factory/blob/main/docs/PRD_GRILL.md).

### What's new in 0.28.2

This patch makes the companion VS Code adapter publishable under the Marketplace's
supported `Testing` category. It does not change FactoryLine runtime behavior,
permissions, or local-first data boundary. Proof Review, Verified Repair Sandbox,
and Workspace Load Advisor give teams a
clear local handoff before a repair or environment change. They are bounded
observations and review packets: no automatic edits, model calls, deployment,
credential access, or production-readiness claim.

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
