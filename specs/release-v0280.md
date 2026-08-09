# Spec: release-v0280
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core
### Description
Release the tested `codex/release-reliability-hardening` source state as Code
Factory `0.28.0`, update every checked-in distribution summary to describe the
shipped Verifier Plane, Diff-to-Proof Review, Verified Repair Sandbox, and
Workspace Advisor, and publish only through the repository's guarded release
workflows.

### User roles
- Maintainer: owns version bump, release tag, and external publication approval.
- Developer: installs the Python package or editor package and needs an accurate
  feature summary and immutable artifact.
- Reviewer: needs a public release URL, checks, and per-channel publication state.

### Requirements (EARS)
- The system shall publish package version `0.28.0` from one immutable commit.
- The system shall update summaries to include the Verifier Plane, Diff-to-Proof
  Review, Verified
  Repair Sandbox, and Workspace Advisor in README, PyPI-derived metadata,
  Hugging Face Space, and JetBrains listing surfaces.
- The system shall store `0.28.0` as the current version and identify
  `0.27.0` as superseded.
- The system shall build and validate the Python wheel, sdist, VSIX, and
  JetBrains ZIP before any release publication workflow is considered ready.
- The system shall emit exactly one status from `published`, `pending`,
  or `blocked` for every configured channel.
- If `required_gate_failed` is true, the system shall reject tag creation and
  release publication for `0.28.0`.
- If `download_total_unavailable` is true, the system shall emit
  `unavailable` rather than infer a total from CI, traffic, or asset counts.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Publish a verified 0.28.0 source state
  Given the release branch contains the tested reliability-hardening source
  When the maintainer runs the release gates and creates tag `0.28.0`
  Then the tag resolves to the tested commit and the GitHub release contains
  the wheel, sdist, VSIX, JetBrains ZIP, and release media

Scenario: Keep public summaries aligned
  Given the source and editor listing files are updated for the same release
  When the publication metadata tests run
  Then no checked-in public summary calls a superseded release the current release
  and every new feature name appears in the intended listing surfaces

Scenario: Do not overclaim channel publication
  Given a protected marketplace workflow is queued or awaiting moderation for
  `0.28.0`
  When the release report is generated
  Then that channel is labelled pending or blocked and its download count is
  reported only when the vendor API or page exposes it
```

## SHOULD - Technical/structural
- ADR references: `docs/RELEASE_CHANNELS.md`, `docs/JETBRAINS_MARKETPLACE.md`,
  `docs/OPENVSX.md`
- Data model: versioned package metadata, immutable Git tag, release assets,
  channel status receipts, and observed download counters
- API contract: GitHub Releases API, PyPI JSON API, JetBrains Marketplace API,
  Open VSX API, Hugging Face Hub API

## SHOULD NOT - Implementation details
- Do not treat a queued workflow, uploaded artifact, or pending moderation as a
  live publication.
- Do not infer downloads, conversion, or adoption from CI runs or release asset
  counts.

## Decision logic (factory candidates)
Declared facts: `required_gate_failed`, `channel_unpublished`,
`download_total_unavailable`, `release_version_is_0_28_0`.

| # | if | then |
|---|----|------|
| 1 | `required_gate_failed == false` and `release_version_is_0_28_0 == true` | allow release tag creation |
| 2 | `required_gate_failed == true` | reject tag creation and publication |
| 3 | `channel_unpublished == true` | emit `pending` |
| 4 | `download_total_unavailable == true` | emit `unavailable` |
