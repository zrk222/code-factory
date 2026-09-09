# Spec: full-stack-ux-harness-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Add a reusable, evidence-bound full-stack code and UX quality harness to Code
Factory. It gives coding agents and human reviewers one predictable path for
checking architecture, production readiness, interaction quality, accessibility,
and ethical UX before release review.

### User roles

- Implementer: supplies implementation and test evidence but cannot approve the
  final interaction judgment.
- Reviewer: records the six human quality judgments with a rationale.
- Release owner: retains the consequential release decision.

### Requirements (EARS)

- When `REQ_SKILL` installs repository guidance, it shall store exactly one
  discoverable internal skill for substantial full-stack or product-facing UI
  work and shall retain repository-specific architecture rules. [R10]
- When `REQ_TEMPLATE` returns a manifest, it shall return exactly 12 core check
  identifiers, exactly 7 additional UI check identifiers when `ui_in_scope` is
  true, and exactly 6 judgment identifiers. [R20]
- When `REQ_CHECK_SET` evaluates `ui_in_scope=true`, it shall return `BLOCKED`
  with `E_UX_CHECK_SET_MISMATCH` unless all 19 required checks occur exactly
  once; for `ui_in_scope=false`, it shall require exactly the 12 core checks
  and shall not label the 7 UI checks as passed. [R30]
- When `REQ_CHECK_EVIDENCE` evaluates a required check, it shall return `BLOCKED`
  unless the check state is `passed`, the provenance is `human_confirmed`,
  `trusted_source`, or `observed_production`, and 1 to 16 non-empty evidence
  files remain inside the workspace with recorded SHA-256 digests. [R40]
- When `REQ_JUDGMENT` evaluates all 6 named judgments, it shall return `BLOCKED`
  with `E_UX_HUMAN_REVIEW_REQUIRED` unless exactly one named human reviewer
  approves truth, regret, transparency, alignment, comprehension, and
  vulnerability with a rationale of 12 to 1000 characters. [R50]
- When `REQ_RECEIPT` completes evaluation, it shall store exactly one
  self-hashed local receipt and return `READY_FOR_HUMAN_RELEASE_REVIEW`
  only when all required checks and all 6 named judgments pass. [R60]
- While `REQ_AUTHORITY` returns a result, it shall return false for execution,
  source modification, approval, deployment, publication, signing, credential,
  provider, connector, and messaging authority. [R70]
- When `REQ_ROUTING` observes at least 1 supported frontend path, it shall return
  `quality-harness:verify` and `prestige:audit` as recommended stages and expose
  `quality_harness` in the IDE/A2A playbook; supported frontend suffixes are
  `.html`, `.css`, `.tsx`, `.jsx`, `.vue`, and `.svelte`. [R80]
- While `REQ_CLAIMS` describes a result, it shall return deterministic evidence
  and heuristic human judgment as separate classes and shall state that the
  local reviewer identity is declared rather than authenticated and that the
  receipt is not certification or measured accessibility, security, conversion,
  or production-fitness proof. [R90]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: complete UI evidence reaches human release review
  Given a UI-scoped manifest with every fixed check passed from an approved origin
  And every check binds a non-empty workspace evidence file
  And the six judgments are approved by a named human with rationale
  When the quality harness verifies the manifest
  Then REQ_RECEIPT returns READY_FOR_HUMAN_RELEASE_REVIEW with a hash-bound receipt
  And REQ_AUTHORITY returns false for release authority

Scenario: an agent cannot approve its own UX judgment
  Given a complete manifest whose reviewer type is agent
  When the quality harness verifies the manifest
  Then REQ_JUDGMENT returns BLOCKED with E_UX_HUMAN_REVIEW_REQUIRED

Scenario: UI evidence cannot be silently omitted
  Given a UI-scoped manifest without keyboard evidence
  When the quality harness verifies the manifest
  Then REQ_CHECK_SET returns BLOCKED with E_UX_CHECK_SET_MISMATCH

Scenario: non-UI work uses only the closed core set
  Given UI scope is false and exactly 12 core checks are present
  When REQ_CHECK_SET evaluates the manifest
  Then REQ_CHECK_SET accepts the 12 core checks and does not mark 7 UI checks passed

Scenario: evidence cannot escape the workspace
  Given a check referring to a path outside the workspace
  When the quality harness verifies the manifest
  Then REQ_CHECK_EVIDENCE returns BLOCKED before REQ_RECEIPT stores a trusted result

Scenario: agent-proposed check cannot become release evidence
  Given a passed required check with agent_proposed provenance and one evidence file
  When REQ_CHECK_EVIDENCE evaluates the check
  Then REQ_CHECK_EVIDENCE returns BLOCKED

Scenario: every judgment requires meaningful human rationale
  Given exactly one named human reviewer approves all 6 named judgments
  And one judgment rationale has fewer than 12 characters
  When REQ_JUDGMENT evaluates the review
  Then REQ_JUDGMENT returns BLOCKED with E_UX_HUMAN_REVIEW_REQUIRED

Scenario: repository guidance is discoverable without replacing local rules
  Given a substantial full-stack task
  When REQ_SKILL installs the repository guidance
  Then REQ_SKILL stores exactly one internal skill and retains repository-specific rules

Scenario: template has a closed review surface
  Given UI scope is true
  When REQ_TEMPLATE returns a manifest
  Then REQ_TEMPLATE returns exactly 12 core checks, 7 UI checks, and 6 judgments

Scenario: frontend work is routed through both quality views
  Given one changed supported frontend path
  When REQ_ROUTING evaluates the changed path
  Then REQ_ROUTING returns quality-harness:verify and prestige:audit
  And REQ_ROUTING exposes quality_harness in the IDE/A2A playbook

Scenario: evidence and judgment remain different claim classes
  Given a ready local receipt
  When REQ_CLAIMS describes the result
  Then REQ_CLAIMS separates deterministic evidence from heuristic human judgment
  And REQ_CLAIMS states the result is not certification or measured outcome proof
```

## SHOULD - Technical/structural

- Data model: versioned JSON manifest and self-hashed local receipt.
- API contract: `factory quality-harness template|verify`.
- Integration: IDE playbook and PR optimizer only; Assembly's existing brick
  authority and Prestige's specialized visual audit remain unchanged.

## SHOULD NOT - Implementation details

- Do not execute arbitrary manifest commands.
- Do not infer a human decision from an agent, CI status, or a boolean alone.
- Do not make AppForge the default path; this harness applies to any substantial
  full-stack or UI change.
