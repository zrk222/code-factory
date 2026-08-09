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
  - local-first
pinned: false
license: apache-2.0
short_description: Reviewable MVPs with verifier, repair, and workspace proof
---

# Code Factory

This Space is the public product surface for
[Code Factory](https://github.com/zrk222/code-factory), an open-source,
proof-first software factory for AI-assisted delivery.

**Why pay for opaque app generators?** Create a reviewable MVP starting state
in minutes—with local receipts, a clear proof path, and an output you can
extend when you are ready. A starter remains blocked until product-specific
proof exists.

The canonical Python package is
[`factoryline-code-factory`](https://pypi.org/project/factoryline-code-factory/).
Release `v0.28.0` is archived under the repository's stable Zenodo concept DOI at
[Zenodo](https://doi.org/10.5281/zenodo.21381405).

Before a PRD becomes a scaffold, run `factory prd grill PRD.md --root .` for a
capped, source-bound clarification sheet with recommendations and answer stubs.
It never rewrites the PRD, invents answers, calls a model, or authorizes a
build. Read the full [PRD Grill guide](https://github.com/zrk222/code-factory/blob/main/docs/PRD_GRILL.md).

### What's new in 0.28.0

Proof Review, Verified Repair Sandbox, and Workspace Load Advisor give teams a
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

The illustrations explain the workflow; they are not UI screenshots or
measured outcome evidence. The quick-start video is rendered from the shipped
Factory Studio interface.

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
