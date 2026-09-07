# Code Factory 0.46.3 — Release Routes That Fail Earlier

> **Candidate status:** this document describes the source candidate. It is
> not evidence of a GitHub tag, PyPI upload, MCP Registry update, Zenodo record,
> Hugging Face Space deployment, marketplace availability, or provider approval.

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

## Next safe action

Finish the remaining approved release slices, run the local package and
release-integrity proof again, and only then request the separately
human-controlled publication actions. Provider response, processing, and
approval remain external states.

## Distribution summary for this candidate

The source package is prepared as a **0.46.3 candidate**. This integration turn
performed local implementation and verification only; it did not upload or
publish to any provider. Keep these states separate when the release operator
uses the prepared artifact:

| Surface | State in this candidate | Evidence boundary |
| --- | --- | --- |
| GitHub | Source/worktree candidate | Local commit/remote read-back is a separate action |
| PyPI | Not uploaded by this change | Requires an authenticated upload and PyPI read-back |
| Hugging Face Space | Not deployed by this change | Workflow now admits `HF_TOKEN` early; Space availability is external |
| Zenodo | Not archived by this change | Archive record and DOI are provider state |
| Visual Studio Marketplace | Not uploaded by this change | Marketplace processing/read-back is external |
| Open VSX | Not uploaded by this change | Namespace auth, processing, and listing read-back are external |

This is a truthful handoff, not a claim that any provider has approved or
received the package.
