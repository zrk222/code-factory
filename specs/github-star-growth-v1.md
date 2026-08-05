# Spec: github-star-growth-v1

Status: draft
SpecFactor-target: 0.75–2.5

## MUST — Functional core

### Description

Give a developer one optional, truthful way to star Code Factory only after a
successful local proof or assembly command, and make the public repository
easy to understand and share without claiming unmeasured adoption.

### User roles

- Developer: a VS Code or JetBrains user who has completed a local FactoryLine command.
- Repository visitor: a person evaluating the public GitHub README.

### Data model

- `Star Code Factory`: the exact optional editor action label. Its sole target
  is `https://github.com/zrk222/code-factory`.
- `prompt version`: the installed editor extension version recorded in local
  editor settings after the optional prompt is shown.
- `README star CTA`: one optional sentence placed after the first-run value
  demonstration; it contains no star count, scarcity, or adoption claim.
- `low-friction value message`: "Why pay for opaque app generators? Create a
  reviewable MVP starting state in minutes—with source-bound receipts, a clear
  proof path, and an output you can extend when you’re ready."
- `social preview source`: `docs/assets/github-social-preview-1280x640.png`, a
  1280x640 PNG derived from a real Factory Studio capture.
- `optional share snippet`: a static Markdown link in
  `docs/CODE_FACTORY_OUTPUT_MAP.md` that a developer may copy into a PR,
  project README, or team message. It contains no project path, feature name,
  receipt, or telemetry data.
- `distribution CTA`: concise source copy for GitHub/PyPI, VS Code/Open VSX,
  JetBrains Marketplace, and the Hugging Face Space. It leads with the
  low-friction value message and retains the proof boundary.
- `community launch drafts`: owner-reviewable Show HN and Indie Hackers copy
  with founder disclosure, a concrete first run, and no fabricated adoption,
  productivity, savings, or scarcity claim.

### Requirements (EARS)

- When `STAR_VSCODE` an eligible FactoryLine command exits with code zero in VS Code, the system shall emit one non-modal, opt-in `Star Code Factory` action when its `prompt version` has not already been recorded.
- When `STAR_JETBRAINS` Run First Proof, Assembly, Continue Assembly, or Verify Receipts exits with code zero without timing out in a JetBrains IDE, the system shall emit one non-modal `Star Code Factory` notification when its `prompt version` has not already been recorded.
- If `STAR_BROWSER_ONLY` the developer selects `Star Code Factory`, the system shall open only `https://github.com/zrk222/code-factory` in the developer's browser.
- While `STAR_NO_AUTOMATION` the optional prompt is displayed, the system shall reject automatic browser opening, telemetry collection, workspace-data transmission, and extra FactoryLine commands.
- The system shall store the `STAR_MINIMAL_LOCAL_STATE` requirement by recording only the installed extension version in the `prompt version` and rejecting workspace paths, receipts, feature names, and command output.
- The system shall render the `STAR_GITHUB_FIRST_VIEW` requirement by rendering the README with the `low-friction value message`, a one-command first run, the existing exact-UI video, and the `README star CTA` before deep reference material.
- The system shall satisfy `STAR_SOCIAL_PREVIEW_SOURCE` by storing the 1280x640 `social preview source` and documenting that a repository owner must upload it through GitHub repository settings before it becomes the live Open Graph image.
- When `STAR_OUTPUT_MAP_SHARE` Code Factory writes `docs/CODE_FACTORY_OUTPUT_MAP.md`, the system shall emit the `optional share snippet` without modifying a user project README or contacting an external service.
- The system shall render the `STAR_DISTRIBUTION_CTA` requirement by putting the `low-friction value message` and an unambiguous first action on every supported distribution source while retaining the local-only and not-production-ready boundaries.
- The system shall satisfy `STAR_COMMUNITY_DRAFTS` by storing community launch drafts for Hacker News and Indie Hackers that can be reviewed and submitted by the owner, without attempting to create an account, send a message, vote, schedule a post, or imply an endorsement.

## Acceptance criteria (Gherkin)

```gherkin
Scenario: A developer completes a local proof in VS Code
  Given the installed version has not shown the optional star prompt
  When an eligible FactoryLine command exits successfully
  Then VS Code offers the defined `Star Code Factory` action without a modal
  And no browser opens unless the developer selects that action
  And the extension records only the prompt version locally

Scenario: A developer completes Run First Proof in JetBrains
  Given the installed plugin version has not shown the optional star prompt
  When Run First Proof exits with code zero and does not time out
  Then JetBrains shows a non-modal notification with the defined `Star Code Factory` action
  And no workspace data is sent

Scenario: A stranger evaluates the repository
  Given the repository README is rendered from the default branch
  When the visitor reads the first section
  Then they see the product outcome, first-run command, exact-UI video, and the defined `README star CTA`
  And no star count, scarcity, or unmeasured adoption claim is shown

Scenario: A developer chooses to share a generated output
  Given Code Factory has created an output map
  When the developer reads its optional share section
  Then they can copy the defined `optional share snippet`
  And Code Factory has not posted it, changed their project README, or transmitted their output

Scenario: A founder prepares a community launch
  Given the public package sources contain the low-friction value message
  When the owner opens the community launch guide
  Then they see a founder-disclosed Show HN draft and an Indie Hackers draft
  And neither draft claims measured adoption, savings, or production readiness
  And Code Factory has not submitted either post

Scenario: Every star-growth contract remains traceable
  Given a release candidate with public source changes
  When the star-growth contract is inspected
  Then STAR_VSCODE is declared
  And STAR_JETBRAINS is declared
  And STAR_BROWSER_ONLY is declared
  And STAR_NO_AUTOMATION is declared
  And STAR_MINIMAL_LOCAL_STATE is declared
  And STAR_GITHUB_FIRST_VIEW is declared
  And STAR_SOCIAL_PREVIEW_SOURCE is declared
  And STAR_OUTPUT_MAP_SHARE is declared
  And STAR_DISTRIBUTION_CTA is declared
  And STAR_COMMUNITY_DRAFTS is declared
```

## SHOULD — Technical/structural

- Use the editor-native persistent settings store; do not introduce a file,
  service, credential, or analytics dependency.
- Use actual Factory Studio media only; do not synthesize a product screenshot.

## SHOULD NOT — Implementation details

- Do not add an editor startup prompt, a background job, or a release action.

## Non-goals and boundaries

- Do not purchase, automate, solicit, or fabricate stars.
- Do not show the prompt at editor startup, before a successful command, or as
  a modal interruption.
- Do not add attribution to generated source files or user-authored project
  README files; the `optional share snippet` is visible only in the generated
  output map.
- Do not add analytics, credentials, external services, or release authority.
- Do not claim a conversion rate, a causal uplift, or a social-preview upload
  until each has its own observed receipt.
- Do not submit, vote on, or coordinate votes for Hacker News or Indie Hackers.
  The owner controls final account-side submission.

## Verification

- `npm test` in `editors/vscode`
- `gradlew.bat test` in `editors/intellij`
- `python -m pytest -q tests/test_target_compiler.py`
- `python -m pytest -q tests/test_publication_metadata.py`
- `python -m pytest -q tests/test_huggingface_surface.py`
- `specline strict github-star-growth-v1 --root .`
- `specline verify-validators github-star-growth-v1 --root .`
