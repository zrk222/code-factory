# Code Factory

[![CI](https://github.com/zrk222/code-factory/actions/workflows/ci.yml/badge.svg)](https://github.com/zrk222/code-factory/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/factoryline-code-factory.svg)](https://pypi.org/project/factoryline-code-factory/)
[![Python](https://img.shields.io/pypi/pyversions/factoryline-code-factory.svg)](https://pypi.org/project/factoryline-code-factory/)
[![Hugging Face Space](https://img.shields.io/badge/Hugging%20Face-Space-ffd21e.svg)](https://huggingface.co/spaces/zrk222/code-factory)
[![GitHub stars](https://img.shields.io/github/stars/zrk222/code-factory?style=social)](https://github.com/zrk222/code-factory/stargazers)
[![Latest release](https://img.shields.io/github/v/release/zrk222/code-factory)](https://github.com/zrk222/code-factory/releases/latest)

> **Generate a local MVP, then catch hollow tests before review.**

> **Why pay for opaque app generators?** Create a reviewable MVP starting state
> in minutes—with source-bound receipts, a clear proof path, and an output you
> can extend when you’re ready. Code Factory is free, local-first, and does not
> call a starter production-ready before the relevant proof exists.

```powershell
factory mvp "Build an approval tracker" --root .
```

[Watch the exact shipped UI in 60 seconds](https://github.com/zrk222/code-factory/releases/download/v0.28.2/code-factory-quickstart-v0171.mp4),
then inspect the evidence path and next action in local Factory Studio. Prefer a
browser preview? Open the [live Hugging Face Space](https://zrk222-code-factory.static.hf.space).

![Exact shipped UI: Factory Studio after generating a local MVP](docs/assets/marketplace/factory-studio-mvp-1280x800.png)

## What it does

- **Start a real project quickly.** Turn one outcome into a contained web, mobile,
  API, CLI, worker, MCP, or agent-UI starting state.
- **Make the work reviewable.** Turn requirements, diffs, proofs, and blockers into
  receipts, Graph Ops, and one fact-derived next action.
- **Keep "done" honest.** Challenge declared validators for hollow tests and keep a
  project blocked until the relevant evidence exists; a green-looking scaffold is
  never called production-ready by default.

## Install

```powershell
pip install factoryline-code-factory==0.28.2
factory mvp "Build an approval tracker" --root .
factory studio --root .
```

## Start here

| If you need to… | Use | You get |
| --- | --- | --- |
| Build a first slice | [`factory mvp`](docs/START_HERE.md) | A contained, app-shaped local starting state |
| Clarify a fuzzy PRD | [`factory prd grill`](docs/PRD_GRILL.md) | Source-bound questions instead of invented requirements |
| Review an AI-assisted diff | [`factory change review`](docs/DIFF_TO_PROOF_REVIEW.md) | A local risk, proof-gap, and next-action packet |
| Inspect delivery state | [`factory studio`](docs/TARGET_COMPILER.md) | Graph Ops, receipts, and the next supported action |
| Verify supplied work | [Verifier Plane](docs/VERIFIER_PLANE.md) | Independent, hash-bound evidence checks |

For the short product map, read the [overview](docs/OVERVIEW.md). For a two-minute
first run, follow [Start Here](docs/START_HERE.md). For full command and contract
reference, browse the [documentation directory](docs/).

## Use it where you work

Code Factory keeps the same local, receipt-bound workflow across the command line,
[VS Code](editors/vscode/README.md), and the [JetBrains plugin](editors/intellij/README.md).
It also provides local stdio [Cursor or OpenCode MCP](docs/AI_CLIENTS.md)
without handing an AI client permission to publish, deploy, approve, sign, or access
credentials.

FactoryLine is free through December 31, 2026. The owner-approved January 1, 2027
JetBrains plan is **$4.95 USD per month**; it is not active until the Marketplace
release and pricing gates are satisfied. See the [Marketplace control-room guide](docs/JETBRAINS_CONTROL_ROOM.md)
for compatibility, pricing, and approval boundaries.

## The proof boundary

Code Factory creates and inspects local artifacts. It does **not** silently call a
model, discover credentials, publish, deploy, sign, approve, message, or grant a
connector. Its deterministic proof receipts bind supplied byte bindings, declared
identities, and evidence; an external runner must separately prove runtime isolation
and network policy. Token, cost, and productivity claims remain unknown until a bound
measurement exists.

```mermaid
flowchart LR
  intent["Plain-language outcome"] --> mvp["Local MVP"]
  mvp --> evidence["Receipts and declared checks"]
  evidence --> review["Graph Ops / review packet"]
  review --> decision["One evidence-backed next action"]
```

Use [PRD Grill](docs/PRD_GRILL.md) before code exists, the deterministic
[contradiction gate](docs/RELEASE_NOTES_0.25.0.md) when requirements collide, [Proof Review](docs/DIFF_TO_PROOF_REVIEW.md)
when a diff arrives, and the [Verifier Plane](docs/VERIFIER_PLANE.md) when a worker
claims it is finished. The local [MCP contract](docs/MCP.md) and generated Mermaid
output map make the same proof context reusable by a client you choose.

## Latest release and deeper material

The current source release is [v0.28.2](https://github.com/zrk222/code-factory/releases/tag/v0.28.2):
Proof Review, the Verified Repair Sandbox, and the Workspace Load Advisor make the
handoff from generated work to a developer's review more legible without granting
automatic repair or release authority. Browse the complete, versioned history in
[CHANGELOG.md](CHANGELOG.md) instead of decoding it from this landing page.

- See the [exact release notes](docs/RELEASE_NOTES_0.28.2.md), [release channels](docs/RELEASE_CHANNELS.md), and [publication guide](PUBLICATION_GUIDE.md).
- Explore the [Concept illustrations](docs/HOW_IT_WORKS_VISUAL.md). They describe the workflow; they are not UI screenshots or measured outcome evidence.
- Read [The approval signal decays when AI-written code becomes routine](docs/HABITUATION_ESSAY.md) for the design and limits of the habituation gate.
- Read [Graph Ops](docs/GRAPH_OPS.md), [proof reuse](docs/PROOF_REUSE.md), and [savings boundaries](docs/SAVINGS_TRACKER.md) when the project needs more than a first MVP.

If Code Factory helped you find a proof gap or get a project moving, you can
[star Code Factory](https://github.com/zrk222/code-factory). The optional action opens
only the repository; it does not send workspace data or change your project.

## License

MIT OR Apache-2.0.
