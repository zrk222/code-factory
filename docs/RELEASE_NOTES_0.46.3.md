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

- **One 0.46.3 identity.** Python package metadata, the local MCP descriptor,
  installer guidance, citation metadata, archive metadata, and release-channel
  guidance name the same core candidate.
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

## Next safe action

Finish the remaining approved release slices, run the local package and
release-integrity proof again, and only then request the separately
human-controlled publication actions. Provider response, processing, and
approval remain external states.
