# Release record reconciliation — 2026-10-27

## Objective

Correct the v0.49.0 release record to match verifiable publication and preview
state while preserving the October 23 precision HOLD as an immutable historical
decision. This is recordkeeping only; it does not publish anything, approve an
editor-marketplace listing, claim a precision gain, or grant a cadence waiver.

## Scope

- Update the `0.49.0` heading and add a concise release-status note in
  `CHANGELOG.md`.
- Add `docs/evidence/owner-publication-supersession-20261027.json` to record the
  later direct user authorization to finish/commit/merge/publish, actual public
  channel evidence, the still-unqualified precision result, the Hugging Face
  source relationship, and release-cadence accounting.
- Preserve `docs/evidence/owner-publication-hold251.json` byte-for-byte.
- Add project-neutral workflow contract and observations under
  `.factory/release-record-reconciliation-20261027/`.

## Requirements and acceptance

1. The changelog no longer calls v0.49.0 pending publication; it identifies the
   GitHub/PyPI publication date and exact release tag/commit.
2. The record distinguishes GitHub release assets from marketplace acceptance:
   VS Code 1.3.0, JetBrains 1.3.0 and 1.3.1 artifacts were attached to GitHub;
   no provider approval is inferred from attachment.
3. PyPI `factoryline-code-factory==0.49.0` is bound to its public wheel and
   sdist SHA-256 values.
4. The public Hugging Face Space revision and its source commit are recorded.
   The source commit is a descendant of the release tag and changes the HF
   workflow, README, preview HTML and its tests; the preview is not represented
   as the exact release-tag source build.
5. The October 23 HOLD and Study 249 value (55%) remain unchanged. The later
   user authorization permits the requested shipment only; no 80% result or
   precision improvement is asserted.
6. The release-train policy is reported accurately. Count public core releases
   from the policy effective time in the rolling window around the v0.49.0
   publication, identify any cap/interval breach, and record that no retroactive
   exception is created.
7. `factory doctor --strict --json`, JSON/link consistency checks,
   `git diff --check`, preservation of the historical HOLD hash, and
   `factory audit workflows` pass with evidence hashes.

## Evidence sources

- GitHub release API/page for `v0.49.0`, including target commit and attached
  artifact digests.
- PyPI JSON API for the exact `0.49.0` distribution.
- Hugging Face Space API and current revision commit metadata.
- Local `release-train.json`, release publication timestamps, and the existing
  historical owner HOLD.
- Direct later user instruction in the current Codex thread, as relayed with
  this task authorization. It does not supersede the measured-precision
  threshold or constitute a cadence exception.

## Category applicability

- Applicable: validation, state consistency, security/privacy, external-effects
  control.
- Not applicable to this documentation/evidence-only change: runtime behavior
  and performance. No executable source or configuration is modified.
- Accessibility is addressed through plain Markdown and structured JSON; no UI
  artifact is changed.

## Execution boundary

No provider write, publication, marketplace submission, release dispatch,
precision-label change, source/scanner edit, or historical-record rewrite is in
scope. A local documentation commit is allowed after the scoped gates pass.
