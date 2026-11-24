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
- When `REQ_VISUAL_ADMISSION` receives an optional visual contract, it shall reject an incorrect SHA-256 pin, a non-loopback target, missing human reviewer or bindings outside 1 through 128 files and 1 through 8 cases, and return `NOT_RUN` without browser execution when execute=false. [R100]
- When `REQ_VISUAL_PIXELS` compares a reviewed baseline with an actual capture, it shall return `FAIL` for a changed RGBA pixel fraction above its pinned 0 through 0.01 threshold or mismatched dimensions/profile, preserve baseline bytes, and return `INCOMPLETE` for a missing baseline. [R110]
- When `REQ_VISUAL_SEMANTICS` executes a case, it shall return `FAIL` unless exactly 1 visible element matches the declared selector, role, name and enabled state and the required terminal text; it shall store the actual accessibility snapshot and screenshot. [R120]
- When `REQ_VISUAL_RUNTIME` executes a declared click, it shall return `FAIL` for mismatching same-action response method/path/status/JSON field or terminal UI text, and return `INCOMPLETE` for a missing response or expiry of the pinned 50 through 10000 milliseconds deadline. [R130]
- When `REQ_VISUAL_PRESTIGE` evaluates a frozen design contract and HTML/CSS source, it shall return `FAIL` unless Prestige reports at least 1 checked token, at least 1 killed mutation and 0 survivors, and shall store source hashes and companion provenance without changing tokens. [R140]
- When `REQ_VISUAL_RECEIPT` finishes an executed run, it shall store candidate, contract, exit code, deadline, cleanup facts, tool identity and artifacts in one receipt, return `INCOMPLETE` for source drift, capture failure, unavailable tooling or unconfirmed cleanup, and retain human-owned release authority. [R150]

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

Scenario: visual execution requires pinned local admission
  Given REQ_VISUAL_ADMISSION has 1 through 128 bound files and 1 through 8 cases
  When execute=false
  Then REQ_VISUAL_ADMISSION returns NOT_RUN without browser execution

Scenario: visual pixels cannot approve their own baseline
  Given REQ_VISUAL_PIXELS compares actual RGBA pixels with a frozen baseline
  When changed pixels exceed the reviewed 0 through 0.01 ratio limit
  Then REQ_VISUAL_PIXELS returns FAIL and preserves baseline bytes

Scenario: visible controls require matching accessible identity
  Given REQ_VISUAL_SEMANTICS expects exactly 1 visible named button
  When its accessible name is missing
  Then REQ_VISUAL_SEMANTICS returns FAIL with an actual screenshot

Scenario: an honest state must match the observed response
  Given REQ_VISUAL_RUNTIME observes a click and its response
  When the UI says Saved but the response status fails its expectation
  Then REQ_VISUAL_RUNTIME returns FAIL
  And a missing response within 50 through 10000 milliseconds returns INCOMPLETE

Scenario: Prestige requires exercised token checks
  Given REQ_VISUAL_PRESTIGE binds a frozen design contract
  When at least 1 checked token and 1 killed mutation leave 0 survivors
  Then REQ_VISUAL_PRESTIGE stores companion provenance and token evidence

Scenario: visual receipts cannot hide source drift
  Given REQ_VISUAL_RECEIPT binds the executed candidate and native process facts
  When source bytes change during capture
  Then REQ_VISUAL_RECEIPT returns INCOMPLETE without release authority
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

## Optional visual-to-behavior execution contract

Owner request: include the visual detector and Prestige integration in core0.50.0
and editor/Devin1.3.6 alongside all current Codex and Claude work. Legacy template
and verify behavior stays compatible; this optional execution is not a seventh
mandatory audit lane and is not a security-recall or native-device certification.

`run_visual_behavior_gate(root, contract_path, contract_sha256, *, execute=False,
out=None)` extends this existing module. CLI `factory quality-harness visual
CONTRACT --contract-sha256 HASH [--execute] --root ROOT [--out RECEIPT] --json`
invokes only its fixed CF-owned child runner, never manifest-provided commands.
The overall child deadline is60seconds; each case is bounded by its timeout.
Missing optional Playwright/Prestige tooling returns INCOMPLETE, without installs.
Pillow is already a ReportLab dependency. Browser execution is a process boundary,
not a kernel sandbox. Only explicitly admitted local test applications are used.

The exact JSON object has schema `factory.visual-behavior.contract.v1`, fixture_only
(the boolean true, declaring non-sensitive local test data), project_id
and journey_id (1..128 characters), candidate (1..128 unique workflow-audit
`{path,sha256,kind}` bindings), reviewer (`{name,type}` with type human and name
1..128 characters), target (HTTP URL with hostname127.0.0.1,localhost,or::1; no
credentials), browser (`{executable,version,platform,width,height}`), design
(null or `{contract,html,css}` with bound files and0..16 CSS bindings), and cases.
Browser executable is an operator-selected absolute path; version is its actual
Chromium version, platform is sys.platform, width is320..1920, height is320..1080,
DPR is1, color scheme light, locale en-US, timezone UTC. Record executable bytes
and Playwright identity. Do not connect to an existing personal browser session.

Each case has exactly id (unique1..128chars), baseline (null or bound PNG), action
(null or `{selector}` for one click), element (`{selector,role,name,enabled}`),
state (`{selector,text}`), response (null or `{method,path,status,field,value,correlation}`),
tokens (0..32 `{selector,property,value}` computed-style expectations), timeout_ms
(integer50..10000) and max_changed_ratio (finite0..0.01). Selectors/text/name are
1..512characters. Response method is GET/POST/PUT/PATCH/DELETE, path begins / and
has no origin/fragment, status is100..599, field is one JSON-object key1..128chars,
and value is a finite JSON scalar. A response expectation requires a click.
correlation is exactly `{header,value}`, each1..128characters, with a simple
HTTP header name of letters/digits/hyphens. The test application, not CF, must
emit that value on the request. CF installs the response listener immediately
before clicking. All same-origin method/path matches count; exactly1 is required
and its request-header value hash must match. Zero/multiple matches remain
INCOMPLETE, including ambiguous background matches. A wrong correlation on the
single response is FAIL. This is correlation evidence, not proof of causality.
Status/field values are measured from that response observed after the
click; the receipt stores value hashes, not raw response bodies or request data.
This supported response subset requires an uncompressed, non-chunked body with
a decimal Content-Length of1..10000000bytes, matching the actual body length.
Missing length, transfer/content encoding or different body length is rejected;
the worker does not silently broaden into an unbounded response-body reader.
This checks API/UI agreement, not database commit truth. Requests outside the
target origin and WebSockets are blocked; service workers are disabled.

Every baseline/candidate/design path stays inside the workspace and is checked
against its supplied lowercase SHA-256. Every source is rehashed after capture.
PNG inputs/captures have at most4million pixels and10million bytes. Different
dimensions or pinned environment is a mismatch; pixel comparison is exact RGBA,
with the permitted changed-pixel fraction explicit in the frozen contract. No
masks, automatic baseline replacement or threshold adjustments are supported.
An absent baseline yields a reviewable proposed capture and INCOMPLETE, not PASS.
Computed-style property names are CSS custom properties or color,
background-color,font-family,font-size,font-weight,line-height,border-radius.

The receipt uses schema `factory.visual-behavior.receipt.v1`, decision
NOT_RUN/PASS/FAIL/INCOMPLETE, the original contract/candidate bindings, execution
facts, browser/companion identity, case observations, actionable findings,
artifact bindings and receipt_sha256 over its canonical core. Successful
execution without mismatches is PASS; observed mismatches are FAIL; absent
required evidence or failed execution is INCOMPLETE. Outputs use a fresh owned
directory and never overwrite source, baseline or existing receipts. Optional
`--visual-receipt` on legacy verify revalidates current hashes and derived
measurements before inclusion. A failing/incomplete optical receipt blocks that
requested quality review; it never approves the six human judgments. Signed
attestation, native-device behavior and release approval remain separate.

Acceptance includes actual local-browser positive and negative cases for pixel
change, hidden/unnamed controls, Saved UI with failed API, stuck state, source
drift, unreviewed baseline changes, and Prestige token deletion. Test unsupported
tooling as blocked rather than a fabricated pass. Synthetic browser cases prove
these detectors, not production accuracy or exhaustive accessibility coverage.

### Execution, replay and privacy details

Cases run in contract order, each with a fresh browser context/page and empty
cookies/storage. One monotonic case deadline starts before navigation and is
shared across navigation, click, terminal-text wait and capture. Before click,
the action selector must intersect the single visible expected role/name control
with the expected enabled state. After the action, compare terminal text,
control semantics and exact stripped computed-style strings. CSS expectations
use browser serialization (for example rgb(255, 255, 255)), not color aliases.
Capture the screenshot and body accessibility snapshot before closing context;
capture failure or expiry is incomplete. Disabled animations are used for the
screenshot, not permission to suppress missing states. No custom page script
is accepted from the contract.

The fixed child invocation is the active sys.executable with -I -B -c and a
CF-owned import of `_visual_child`, passing only the CF package root, workspace,
contract path/pin and fresh output directory. Existing `run_cli_detailed`
supervises the process tree: Windows Job Object or POSIX process group, bounded
streams65536bytes, timeout60seconds and existing owned-descendant cleanup. Its
cleanup_confirmed and streams_closed must be true, exit_code0, duration at most
60000ms, with no timeout/launch/overflow/cancel/reason failure. The parent stores
failure receipts even when no child observations JSON exists; discovered bounded
PNG/JSON artifacts remain partial evidence. No process-tree or shell fallback
is introduced. Only the explicitly selected browser is launched by the fixed
capture runner, and no personal browser profile is attached.

Receipt top-level fields are exactly schema, contract, candidate, decision,
execution, identity, cases, findings, artifacts, prestige, deadline_seconds,
authority, claim_boundary, receipt_sha256; returned path is outside the hash.
contract is `{path,sha256,bytes}`; artifacts are `{path,sha256,bytes,kind}`.
authority is `{release:false,approval:false,publication:false}`. Each finding is
`{code,detail,case_id,outcome}`, where outcome is FAIL or INCOMPLETE. Decision
precedence is NOT_RUN before execution; after execution any INCOMPLETE finding
means INCOMPLETE, otherwise any finding
means FAIL, otherwise PASS. A parent/tool failure also means INCOMPLETE.
Canonical hashing uses CF canonical_json_bytes (sorted JSON object keys,
UTF-8, no nonfinite values), with receipt_sha256 omitted from the hashed core.

identity records the harness source SHA, Python/Playwright and imported
Pillow version identity,
selected executable SHA, actual browser version, sys.platform and viewport.
NOT_RUN identity contains only the harness SHA. execution is null for NOT_RUN;
otherwise existing runner facts excluding raw stdout/stderr/output, plus
duration_ms, deadline_seconds, argv_sha256 and stdout/stderr SHA. cases contain
id, capture_error, artifacts, pre-action control observation, action_identity,
post-action element_count/visible/enabled/accessible_matches/accessible_snapshot,
state_text/state_count/state_visible, response_count and optional response,
tokens, screenshot, duration_ms and timed_out as observed. A response stores
method,path,status,field_present,value_sha256,correlation_sha256. A style stores
selector,property,value,count. Errors can leave partial case fields; those never
pass. Pixel comparison is recomputed from artifact bytes during replay rather
than trusting a supplied numeric score. Accessibility identity, cardinality,
state, expected-value hashes and style comparisons are likewise recomputed.

Prestige integration calls existing public `report_tokens(html, design, css)`
and `verify_tokens(html, design, css)` on the pinned HTML and design path, joining
bound CSS files with newlines. It stores `{report,mutations,provenance,bindings}`.
Require report.n_checked>=1 and n_passed==n_checked, mutations.mutants_killed>=1,
mutants_total==mutants_killed and each mutation.killed exactly true. Re-run these
deterministic checks on receipt verification and compare the complete recorded
outputs/provenance. Missing requested companion tooling is INCOMPLETE; zero
coverage or surviving mutations is FAIL. Prestige source-token evidence is
distinct from computed-style expectations; neither certifies visual taste.

Replay rehashes the original contract and all candidate/design/baseline/capture
artifacts, requires current harness/browser profile identity and case count,
re-derives observations as above, and preserves recorded incomplete findings.
Global artifact registrations must exactly contain each case's screenshot and
accessibility artifact plus one producer observations JSON. Paths must be unique;
the screenshot reference must match its registered byte binding. Producer cases,
identity, Prestige output and artifact references must match the outer receipt;
the accessibility JSON must exist and remain hash-current. Removing registrations
or altering a screenshot reference cannot evade replay through resealing.
Legacy quality verification includes optical evidence only when explicitly
requested; only a current PASS is accepted. NOT_RUN/FAIL/INCOMPLETE blocks that
inclusion and never substitutes for the six human judgments. Legacy callers
omitting optical evidence retain their original receipt shape.

These local unsigned receipts detect byte drift, not malicious fabrication by
a workspace writer. Reviewer identity, fixture-only declaration, served-build
identity and captured browser/API observations are not independently
authenticated. A signed external attestation is still required when the release
policy demands it. Screenshots and accessibility snapshots can contain fixture
text; keep them locally inside the owned output directory and never upload
automatically. Do not use production or sensitive user data. Do not log request
headers/bodies, raw response bodies/values, credentials or console text. Error
receipts expose bounded error classes/codes rather than exception messages.
