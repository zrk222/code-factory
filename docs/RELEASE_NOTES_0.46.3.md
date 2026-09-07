# Code Factory 0.46.3 — Release Routes That Fail Earlier

> **Published status:** the `v0.46.3` GitHub release and tagged artifacts are
> published. Provider availability and download counters below are read-backs
> from the providers on 2026-09-07 UTC; they are not approval guarantees.

## Public update summary

### 6 mandatory audit lanes. 136 coded rejection conditions. One human-owned release decision.

The source inventory reports **81 lane-specific and 55 cross-cutting**
rejection conditions. Those counts describe code paths, not a promise that
every project runs 136 tests; observations depend on approved scope, configured
engines, and supplied evidence.

Code Factory helps people and coding agents turn a request into a reviewable
path: intent, forbidden behavior, gate, test, evidence, and a human-owned
decision. The six audit lanes cover workflow invariants, tenant isolation,
failure recovery, consumer compatibility, data migrations, and performance or
resource regressions. Missing evidence remains incomplete or blocked.

## What changed in this candidate

- **Independent evidence, not agent self-report.** A signed execution
  attestation binds the candidate and plan to the runner executable, nonce,
  cleanup, memory/latency observations, and target/known-bad artifacts. A
  supervised local run cannot satisfy the independent assurance lane.
- **Defects measured against reality.** A reviewed buggy/fixed corpus now
  produces case-level findings and per-category precision/recall. A missed
  known defect or failed fix blocks the benchmark receipt; no replay command
  is run by the adapter.
- **Faster feedback without unsafe reuse.** A dependency DAG produces a
  topological `RUN`/`REUSE`/`SKIP`/`BLOCK` plan. Unknown closure, side effects,
  assurance drift, and blocked dependencies fail closed. An incremental plan
  can be compared with a full baseline before a skip is reviewed.
- **Failures can be reproduced, repaired, and explained.** The senior
  assurance controls bind a fresh process replay to exact source,
  dependencies, policy, inputs, and the sealed contract; compare the original
  failure with a proposed repair and negative controls; explain every reuse
  decision across policy/dependency/toolchain/environment fingerprints; and
  emit a plain failure briefing with affected scope, a runnable reproducer,
  uncertainty, next fix, and receipt-linked evidence. Changed expectations
  require an explicit reviewer and reason. Replay is bounded
  process/workspace isolation, not a kernel/container sandbox.
- **Mission Control visibility.** Graph Ops now projects these receipts as
  read-only evidence nodes, recomputes local self-hashes, and marks blocked or
  non-equivalent plans for review without executing the runner or changing
  release authority.
- **One 0.46.3 identity.** Python package metadata, the local MCP descriptor,
  installer guidance, citation metadata, archive metadata, and release-channel
  guidance name the same core candidate. The current editor-channel mapping is
  FactoryLine for VS Code **0.9.5** and FactoryLine for JetBrains **0.9.3**;
  the marketplace version is an external provider read-back, not implied by
  this local source candidate.
- **Hugging Face route admission.** The Space workflow now checks its declared
  `HF_TOKEN` before it checks out source, prepares Python, validates metadata,
  installs the client, or constructs an upload call. A missing token fails with
  a short actionable reason instead of a late upload failure.
- **Static route proof.** `factory release integrity --root . --json` checks
  the ordered admission boundary as `HUGGINGFACE_AUTHORIZATION_EARLY` and keeps
  `HUGGINGFACE_METADATA_PREFLIGHT` ahead of client installation and upload.
- **More reliable Windows shutdown evidence.** Bounded verifier processes run
  in an isolated process group. A raced `taskkill` status is accepted only once
  the supervisor and its captured streams have closed; this is not a sandbox or
  proof that an unobserved descendant cannot exist.
- **Clear limits.** The local proof only reads repository text. It cannot read
  a credential, contact Hugging Face, dispatch Actions, publish a Space, or
  prove external availability.

## Why it matters

Release work has two parts: the artifact and the route that carries it. A green
build cannot repair a workflow that reaches a missing secret only after the
candidate has been prepared. This slice makes that route failure visible at the
first declared boundary while preserving the existing independent artifact,
policy, and provider gates.

The new senior-engineering layer closes a different gap: a green report is not
the same as independent observation, real-defect sensitivity, or safe proof
reuse. It makes those distinctions visible before a human decides.

## Current provider read-back

- **GitHub:** `v0.46.3` release points to the verified commit and carries the
  Python, VS Code, JetBrains, and collateral assets.
- **PyPI:** `factoryline-code-factory` is at **0.46.3**.
- **Hugging Face:** `zrk222/code-factory` is deployed at the published route;
  the Space API read-back reports the deployed revision and running state.
- **Open VSX:** `zrk222.factoryline-vscode` is **0.9.5** with **2,692
  provider-reported downloads**.
- **JetBrains:** the FactoryLine update passed the eight compatibility
  verifiers and the Marketplace publish workflow; the listing read-back shows
  **169 downloads** and no unapproved update flag.
- **Visual Studio Marketplace:** the public listing read-back remains **0.9.4**
  with **220 provider-reported downloads** (and 2 installs). The 0.9.5 route is
  not published because the protected `VSCE_PAT` credential is absent; this is
  the only unresolved provider-side publication gate.

These states are intentionally separate: a successful local build or GitHub
workflow does not imply Microsoft Marketplace processing or approval.

## Distribution summary for the published release

The source package is published as **0.46.3**. Keep artifact, provider
processing, and approval states separate when reporting this release:

| Surface | Current state | Evidence boundary |
| --- | --- | --- |
| GitHub | Published `v0.46.3` release and assets | Release URL and asset list |
| PyPI | Published `0.46.3` | PyPI JSON read-back |
| Hugging Face Space | Deployed | Space API revision/read-back |
| Zenodo | No new archive was created in this release | DOI/archive state is separate |
| Visual Studio Marketplace | Public `0.9.4`; `0.9.5` awaiting credentialed upload | Gallery API read-back; `VSCE_PAT` gate |
| Open VSX | Published `0.9.5` | Registry API read-back |

This is a truthful handoff, not a claim that any provider has approved or
received the package.
