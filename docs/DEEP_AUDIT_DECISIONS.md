# Deep audit decisions

Turn bound analyzer reports into a prioritized repair queue, without letting the
analyzer approve its own work.

## Current entry point

`factoryline.deep_audit.execute_deep_audit(plan_path, trust_root_path,
trust_root_sha256, workspace_root)` verifies the signed plan and pinned trust
root, normalizes each target and separate canary report, evaluates the approved
rules, then rechecks input bindings before persisting a receipt.

The pure `evaluate_deep_audit` helper does not authenticate caller dictionaries.
Use the execute entry point for signed intake. No scanner or repair is executed.

## What blocks readiness

- Missing exact failing, unsuppressed canary: `HOLLOW_DEEP_AUDIT`.
- Unapproved suppression: `DEEP_SUPPRESSION_UNAPPROVED`.
- Unknown introduced error: `DEEP_UNKNOWN_ERROR`.
- Insufficient trace or missing ordered source-to-sink flow: `DEEP_TRACE_INCOMPLETE`.
- Signed total/new threshold exceeded: `DEEP_RULE_THRESHOLD`.
- Invalid or missing inputs raise a closed error; they never become a clean receipt.

Each repair item includes its rule/obligation, location where available,
remediation and consequence. Signed severity controls priority. Cross-analyzer
and cross-category clusters help route investigation; they do not prove causation.

All mapped results count toward the total threshold, even results labelled pass,
absent or suppressed. Only new, updated and unbaselined results count toward the
introduced threshold. This conservative policy may require review of producer
output; relabelling findings cannot silently create a green decision.

## Evidence and limits

Receipts live in `.factory/deep-audits/<content-sha256>.json`. Identical writes
are idempotent; differing existing contents fail. An interrupted write may leave
an incomplete receipt, which status rejects rather than reporting readiness.
Receipts bind candidate, signed envelope, normalized reports, rules and canaries.

`deep_audit_status(workspace_root)` reads the latest file by modification time;
it verifies its self-hash, filename and decision consistency. It does **not**
authenticate the writer, prove freshness, or authorize release. A local writer
can recompute a self-hash. Linked directories and invalid receipts are INCOMPLETE.

The only successful decision is READY_FOR_HUMAN_REVIEW, never approved. Evidence
can establish that these checks passed, not that the candidate has no defects.
Graph Ops projects up to 50 finding chains with a complete receipt reference and
explicit truncation. Nodes remain unassessed: receipt hashes do not establish
signer authenticity. Projection detects changes from its observed receipt hash.

## Independent attestation and freshness

An external verifier can now sign a `factory.deep-audit-attestation.v1` DSSE
document. `factory deep-audit attestation <attestation.json> --receipt
<receipt.json> --trust-root <trust.json> --root <workspace>` verifies the signer
against the operator-pinned trust root, binds the exact receipt, plan, candidate,
rules, canary set and complete report maps, and enforces the timezone-aware
freshness window (one hour by default, never longer than 24 hours). The verifier
identity must be independent of every analyzer. The result is
`DEEP_AUDIT_ATTESTATION_VERIFIED`; it is still review-only and carries
`authority: none`.

For a repair comparison, pass `--before-attestation`, `--after-attestation` and
`--trust-root`; add `--require-attestation` to make both attestations mandatory.
Any supplied attestation is verified even in compatibility mode, and a bad or
stale one blocks. The default three-argument comparison remains self-hash-only
for backwards compatibility. Attestation verification authenticates signer,
binding and freshness, not analyzer semantic correctness or release approval.

## Compare a repair

`factory deep-audit compare --root <workspace> --before <relative-receipt.json>
--after <relative-receipt.json>` reads two explicit receipts without modifying
files. The repair-loop adapter returns:

- `blocked`: malformed evidence, changed rules/canaries or analyzer coverage.
- `regressed`: new finding identities or new blocker identities.
- `stagnated`: no finding reduction and blockers remain; stop and review.
- `repair_required`: fewer findings, no new findings/blockers, more review work.
- `approval_required`: the later receipt has no blocking repairs and requires a human.

Exit 0 means approval_required, never approved; every other comparison state
exits 1. Results bind both receipt digests and list resolved/introduced findings,
new blockers and remaining repair guidance. The caller supplies chronology;
the comparison does not prove freshness, source provenance, or report authenticity.
It does not grant a budget, retry automatically, authorize repairs, or close an
existing human review. Supplying self-hashed fabricated evidence remains outside
this local authenticity boundary; re-run signed intake for current evidence.

## IDE and agent access

Use `factory deep-audit evaluate --plan <signed.json> --trust-root <trust.json>
--trust-root-sha256 <sha256> --root <workspace>` to evaluate existing reports and
write the local receipt. No scanner, repair or release runs. Required paths are
explicit; JSON output is always produced. Exit 0 means ready for human review,
1 means blocked, and 2 means invalid inputs or an execution error.

Use `factory deep-audit status --root <workspace> --json` or the read-only MCP
tool `factory.deep_audit_status` to inspect it. Status returns exit 1 for NOT_RUN
or INCOMPLETE too: missing evidence is not a green audit. MCP accepts no arguments
and cannot start an audit. The IDE playbook identifies when to use this tool.

Mission Control includes the deep-audit evidence and marks BLOCKED/INCOMPLETE as
blockers. A ready receipt requires human review, never approval. Its profile now
measures six readers; these local timings do not establish an overall speedup.

## Plan: deeper code penetration audits

### Objective and claim boundary

Build a candidate-bound, repeatable security assessment that tries to find
reachable weaknesses across the complete declared product surface. The current
`factory audit security` lane is a bounded Python AST pattern scan; the current
`factory audit patterns` and `guard-paths` lanes inspect explicitly configured
Python symbols; ForgeLine `--repo-wide` is an inventory/QA signal, not an exploit
test. The deep-audit evaluator currently validates supplied analyzer reports,
rules, and canaries; it does not launch scanners or exercise the application.
The scan of this repository also showed that ForgeLine can report unsupported
TSX parsing. These are material coverage gaps, not reasons to call current
results clean.

The product must not claim that software is defect-free or universally
“certified.” Target claim: **security evidence is complete for the named
candidate and declared scope, the configured challenge set was detected, no
unaccepted blocker remains, and a specialty security reviewer independently
examined the exact evidence**. Missing, unparsed, timed-out, stale, or
unsupported coverage is `INCOMPLETE`/`BLOCKED`, never pass. Passing results
remain advisory until the human release authority decides. An AI reviewer is a
separate technical review pass; it does not impersonate an eligible human
reviewer, satisfy branch protection, or certify security.

### Enterprise reference toolchain

Tool selection below reflects official project documentation checked
2026-09-25. The tools are complementary: each result is scoped to the inputs and
analysis it actually supports. Pin tool binaries/actions/container images by
immutable version or digest; record advisory database timestamps, rule packs,
configuration digests, exit status, and resource limits in every receipt. A
scheduled update lane should propose tool/database changes, replay the challenge
suite, then promote reviewed pins. Never use a floating `latest` in a gated
receipt.

| Layer | Recommended tooling | Required use and limits |
| --- | --- | --- |
| Requirements and attack model | [OWASP ASVS 5.0.0](https://owasp.org/projects/asvs) | Version every mapped requirement (for example `v5.0.0-...`); derive threat cases from actual trust boundaries and entry points. ASVS is a verification standard, not a scanner or certification. |
| Multi-language SAST and dataflow | [GitHub CodeQL](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/) CLI/query packs plus reviewed custom path queries | Primary semantic engine for Python and JavaScript/TypeScript, including `.tsx`; require a successful database build, report each extracted language/build mode, and add custom source/sink models for project-specific CLI, MCP, hook, subprocess, filesystem, and credential flows. Standard and custom query results are distinct. |
| Independent SAST cross-check | [Semgrep Pro Engine](https://semgrep.dev/products/pro-engine/) where an enabled, licensed deployment covers the target | Run curated rules and taint checks as an independent engine. Confirm exact language, cross-function/interfile mode, and PR-vs-full-scan behavior before counting coverage; do not generalize cross-file support from one language to all languages. If the required plan is unavailable, mark this layer unavailable rather than silently substituting Community rules. |
| Resolved dependency inventory and CVEs | [Syft](https://github.com/anchore/syft) SBOMs plus [OSV-Scanner V2](https://google.github.io/osv-scanner/usage/) on supported lockfiles and built artifacts | Produce candidate-bound SPDX or CycloneDX for source/build output and packaged wheel/editor artifacts; scan resolved lockfiles and artifacts, prefer lockfiles over version-range manifests, and report unresolved/private dependencies. Do not treat a manifest-only match as the deployed dependency graph. |
| Repository, config, image, and secret checks | [Gitleaks](https://github.com/gitleaks/gitleaks) over declared Git history; [Trivy](https://trivy.dev/docs/latest/references/terminology/) for filesystem/image vulnerabilities, misconfiguration, secrets, and licenses | Gitleaks history range must be explicit (all available refs for baseline, exact commit range for PR delta); redact secret values. Run Trivy scanner classes separately and report their coverage individually. SBOM generation is not itself a vulnerability scan. |
| API/runtime probing | [OWASP ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/) with the [OpenAPI job](https://www.zaproxy.org/docs/desktop/addons/openapi-support/automation/) | Run passive and active scans only against a disposable local/staging target explicitly bound to the candidate; import the API spec, use synthetic accounts/data, and define auth, rate, time, and request budgets. Active scans can alter target state; external targets require explicit written authorization and separately approved scope. |
| Parser and input fuzzing | [Atheris](https://github.com/google/atheris) for Python; [Jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js) for Node/JS/TS | Add coverage-guided harnesses for CLI/MCP JSON, manifests, audit receipts, hook events, and path/config parsing. Keep minimized crashers as regression fixtures. Atheris currently documents Linux (32/64-bit), macOS, and Python 3.11–3.14; constrain its runner matrix to those combinations and mark Windows/other OS combinations untested. Fuzzing complements, but does not replace, stateful authorization tests. |
| Supply-chain posture | [OpenSSF Scorecard checks](https://github.com/ossf/scorecard/blob/main/docs/checks.md), [SLSA v1.2 provenance](https://slsa.dev/spec/v1.2/provenance), and [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations) with artifact-to-source digest comparison | Use Scorecard for repository/process controls, not source-code SAST. Verify provenance and artifact identity against the candidate and authorized workflow; mere presence of an SBOM, signature, or attestation is not verification. Check the GitHub plan entitlement for private repositories before relying on this provider path. |

The baseline scanner lane must be runnable without a paid service where a
capable free/local option exists. Semgrep Pro is an explicitly budgeted
complement, not a hidden dependency. Enterprise purchase or hosted scanning
must not be assumed until access, licensing, data residency, retention, and
source-upload controls are approved. For every tool, record version and enabled
features from the actual execution, not from this plan or a product page.

Semgrep's documented cross-file mode applies to full scans and can fall back to
single-file analysis under resource pressure. Adapters must record the actual
analysis mode and reject that downgrade as `INCOMPLETE` when cross-file analysis
is required; a successful process exit cannot satisfy the deeper requirement.
See the [cross-file analysis documentation](https://docs.semgrep.dev/semgrep-code/semgrep-pro-engine-intro).

### During-run progress and after-run resolution packets

The operator must be able to tell what is running before the final report is
ready. The Muse hook currently exposes a coarse, non-streaming progress label
while its bounded synchronous checks run; the completed hook output is the
authoritative result. The target deep-audit runner should emit a durable stage
event at inventory, each analyzer, runtime/fuzz lane, normalization, and
specialty review. Each event carries the candidate digest, stage, start time,
heartbeat, tool identity, and current coverage count. A killed, stale, or
missing stage event is `INCOMPLETE`; progress must never be presented as a
finding-free result.

Every finding and every coverage gap produces a resolution packet with:

- stable finding ID, candidate digest, severity, confidence, analyzer/rule and
  version, file/line or trace, and the exact supporting evidence;
- reachability/preconditions and affected trust boundary, including the source,
  transformations/guards, and sink when the analyzer can establish them;
- a prioritized, safe resolution proposal that says what to change and what
  behavior to preserve; any uncertain inference is labeled for review;
- a regression case to add or run, the exact verification command/tool and
  expected result, plus before/after evidence links;
- disposition state, human owner, due date, rationale, and suppression expiry
  where applicable. A suppression is not a resolution and cannot hide a gap.

Order the actionable queue by critical/high exposure, reachable attack paths,
privilege and tenant impact, then medium/low findings and quality issues. Keep
known findings visible even when another parser or runtime lane is incomplete.
For each incomplete lane, state the affected paths/languages, missing parser or
tool, failed command/timeout, exact prerequisite, and rerun command. If evidence
does not support a safe concrete fix, say what must be inspected and request a
specialty reviewer; never manufacture certainty. A specialty AI reviewer may
challenge or refine a proposed resolution against the bound source and evidence,
but it cannot apply edits, accept risk, or replace an eligible human approver.

“Full code depth” is a measurable inventory and analysis condition, not a
scanner-count claim. Enumerate every tracked executable file, generated-code
boundary, build target, runtime entry point, API/MCP/tool handler, privileged
operation, dependency input, and deployment surface by language and digest.
Parse all declared supported source or record each exact exclusion; then
connect framework-aware entry points through aliases, helpers, cross-file and
interprocedural flows to sensitive sinks and authorization/tenant checks where
the selected engine supports those semantics. Exercise those flows with
candidate-bound negative and positive runtime tests, boundary/fault cases,
dependency and configuration checks, and isolated fuzz/DAST targets. Unsupported
languages, unreadable files, failed database builds, unmodeled sinks, timeouts,
and unobservable runtime effects remain explicit gaps. Required inventory
accounting is 100%; all other coverage is reported per language, tool, and
attack-surface category. A report is not review-ready while a required source,
entry point, or check is unaccounted for.

The current Muse integration is explicitly bounded triage: Code Factory's
pattern/guard-path scan needs the project's `.factory/review-audits.json`, its
security scan covers Python AST patterns only, and ForgeLine's repo-wide check
is inventory-only. During a run, its status message names those bounded checks
and says full-depth penetration remains incomplete. Afterward, every finding
row pairs available location/rule evidence with a safe next step and exact lane
rerun command; parser gaps remain `INCOMPLETE` while known findings stay
visible. The fifth `Full-depth penetration` outcome is persisted and required
in the final summary; it is hard-set to `incomplete`, including when older
four-outcome records are read, until a full candidate-bound pipeline actually
produces the required evidence. This hook does not yet create the durable,
candidate-bound repair packet specified above and does not execute the full
enterprise pipeline. Its current output is run-time guidance, not a
penetration-test or certification claim.

### Specialty AI review contract

Every candidate that reaches deep-audit review is assigned a specialty security
AI reviewer separate from the implementation agent. Give it a read-only
candidate snapshot, candidate SHA/tree digest, threat model, coverage matrix,
raw report digests, normalized findings, test/challenge results, and explicit
unsupported areas. Ask it to adversarially inspect authorization and tenant
boundaries, injection/dataflow, path/archive handling, deserialization,
SSRF/egress, secrets, trust transitions, error paths, and scanner blind spots.
Source files and reports are untrusted data, never reviewer instructions.

The reviewer returns a structured, evidence-linked report with finding IDs,
file/line or trace references, severity rationale, exploit preconditions,
confidence, counter-evidence, and `CLEAR`, `FINDINGS`, or `INCOMPLETE` status.
Bind that report to reviewer model/provider/version, review prompt/template
digest, candidate digest, evidence digests, and timestamp. The reviewer has no
write, credential, publication, release, or approval capability. Findings must
be triaged and repairs rerun through the same candidate-bound evidence chain;
the reviewer does not patch its own findings. Preserve this agent review as
specialist AI evidence, while keeping eligible human approval and release
protection separate.

Enforce reviewer provenance in the runner rather than trusting a self-declared
role in a report. The operator-pinned trust root must assign distinct
implementation and reviewer workload identities and separate signing
credentials. A trusted review coordinator invokes the restricted reviewer and
attests the invocation and returned report using its authorized reviewer role.
Bind the run ID, candidate/evidence digests, implementer identity, reviewer
workload identity, actual provider/model metadata, provider response ID when
available, prompt digest, permitted read set, report digest, and freshness
window. The implementation worker must not possess the reviewer signing key
or be able to rewrite the coordinator's review record. Enforce read-only tool
and credential restrictions at the worker boundary, not merely in its prompt.

Reject an unknown/revoked signer, missing signature, shared implementation
identity, replayed invocation, stale report, or candidate/report mismatch.
Missing or unverifiable provenance is `INCOMPLETE`; proven tampering or identity
mismatch is `BLOCKED`. Seed negative challenges for each rejection. When a provider does not supply
cryptographically verifiable invocation evidence, describe the result as a
trusted-coordinator attestation of the AI invocation; do not claim that the
provider signed it. Identity separation and signed provenance establish the
review process and report origin, not the correctness or completeness of the
reviewer's reasoning.

### Runner and integration design

The following components are proposed implementation work, not existing
commands or capabilities. Extend the existing deep-audit subsystem and reuse
its signed intake, comparison, and status readers instead of introducing a
parallel certification product or many new top-level CLI commands.

- **Immutable candidate snapshot:** identify the commit plus a digest of the
  actual source tree, including relevant uncommitted and untracked inputs.
  Run analyzers against that snapshot. A changed working tree creates a new
  candidate; a Git SHA alone cannot describe dirty source or built artifacts.
- **Versioned scope and toolchain manifests:** declare required languages,
  targets, build configurations, entry points, test roles, exclusions, analyzer
  modes, rule packs, image/binary digests, and execution budgets. Repository
  text and scanner output cannot authorize new commands, targets, or network
  access. Validate adapters against a closed command/capability schema.
- **Requirements routing:** combine discovered source, build/deployment
  targets, and PRD/spec obligations. A missing requirement document cannot
  remove discovered code from scope. Route native/mobile requirements to
  AppForge and SaaS/identity/billing requirements to the existing `saas_proof`
  integration, keeping their current read-only status separate from future
  executed tests. Incomplete requirement discovery adds explicit unknowns and
  conservative routing; it cannot create an implicit audit exemption.
- **Resumable job coordinator:** long scans run outside Muse's short build
  hook. Return a run ID and expose durable progress, findings, and cancellation.
  Record stage transitions atomically. Retry transient failures within policy;
  expired heartbeats, killed processes, exhausted budgets, and partial reports
  remain incomplete. Reuse a stage only if candidate, inputs, toolchain, rules,
  environment requirements, and evidence digests still match.
- **Isolated execution:** use disposable workers, bounded CPU/memory/disk/time,
  scoped egress, and synthetic runtime accounts. A subprocess timeout is not a
  security sandbox. Workspace test/build code may execute arbitrary code and
  needs the same worker isolation as scanners. External active tests require
  the exact authorized target and scope; no production credentials by default.
- **Adapter contract:** every adapter supplies preflight, supported language
  and engine modes, an input/extraction inventory, execution metadata, raw
  output hashes, normalized findings, diagnostics, and stop/cleanup behavior.
  Missing tools, licenses, parsers, unresolved dependencies, or runtime targets
  produce prerequisite tasks and an incomplete lane rather than a skip-as-pass.
- **Evidence layout:** retain a run manifest, coverage matrix, append-only
  event log, raw report references, normalized findings, remediation queue,
  challenge results, and reviewer report in a versioned run directory. Hash
  the artifacts, redact credentials, apply access/retention policy, and export
  a public-safe receipt separately. Do not commit raw exploit or secret data
  automatically. A hash proves integrity, not who produced or reviewed it.
- **Muse, CLI, MCP, and IDE views:** render the same run state and finding IDs.
  Preserve the current read-only MCP status tool; a future execution capability
  must have explicit target, budget, cancellation, and authorization contracts.
  Use host-supported status/progress facilities and a pollable run view for
  intermediate actions. Keep the existing hook's coarse progress label honest
  until this runner is implemented.

During execution, emit stage-start, heartbeat, finding-observed,
coverage-gap-observed, stage-completed, stage-failed, and run-completed events.
Events include a sequence number, run/candidate identity, timestamp, stage,
measured counters, and evidence references. New actions are provisional until
their evidence is normalized and reviewed. Do not invent a completion percentage
when the total work is unknown. Stream only redacted, bounded, untrusted data.

After execution, export a complete prioritized remediation queue and a compact
summary linking to it. Record issue states as observed, proposed, patch-prepared,
retest-pending, resolved, reopened, or accepted-risk. An accepted risk is never
counted as a repaired issue. A proposed fix carries its preconditions, affected
behavior, suggested regression case, exact rerun command, expected result,
owner, and evidence links. When a fix is authorized, apply it in an isolated
candidate, rerun the affected analyzer and tests, inspect new findings, and
request independent review. Close the issue only on new matching evidence;
reaching a retry budget or finding a new regression leaves it open.

### CI execution profiles

| Lane | When | Work | Blocking behavior |
| --- | --- | --- | --- |
| Pull request | Every PR and candidate change | Changed-surface inventory; CodeQL and enabled Semgrep rules; secret diff scan; policy/guard checks; targeted unit, authorization, and challenge tests; PRD/spec routing to AppForge/SaaSForge | Block on critical/high findings, inventory uncertainty in changed security-sensitive paths, failed required challenge, stale policy, or missing reviewer handoff. Surface full-scan-only checks as pending, not passed. |
| Complete repository | Scheduled full scan and security-sensitive merges | Full source/branch inventory; all supported CodeQL databases and rules; full-history Gitleaks; lockfile/artifact SBOM and OSV scan; Trivy configuration/image modes; complete mutation/challenge suite; fuzz budget; local disposable ZAP/API suite | Any skipped/truncated target, tool failure, timeout, unsupported grammar, unresolved dependency, or incomplete fuzz/DAST scope is `INCOMPLETE`. Retain artifacts and database timestamps for comparison. |
| Release candidate | Before protected release admission | Repeat full-repository lane on exact built artifacts; compare artifact and source SBOMs; verify SLSA/GitHub provenance, signatures, and package digests; run specialty AI review against exact evidence; collect separate eligible human approval | Candidate SHA, artifact digest, reports, scanner versions, reviewer report, and approval subject must all match. No report or agent verdict publishes/releases on its own. |

Run expensive engines and fuzz targets with policy-configured CPU, memory,
network, request, and wall-time ceilings. Derive practical ceilings from a
baseline pilot and record measured consumption; do not invent a universal
runtime budget. Exhausting a ceiling is a visible incomplete state, never a
clean result. Use ephemeral, least-privilege runners; do not pass production
credentials or customer data to analyzers, fuzz harnesses, or reviewer agents.

### Target pipeline

1. **Candidate and attack-surface inventory.** Bind commit/tree digest, changed
   paths, build targets, languages, runtime entry points, dependency and lock
   files, deployment descriptors, generated/vendor exclusions, and testable
   interfaces. Produce a per-language/per-target coverage matrix with explicit
   reasons for every exclusion. Detect truncated file lists, ignored tracked
   source, nested repositories, symlinks, and analyzer input limits. An
   unrecognized executable source type or failed inventory blocks a complete
   coverage claim.
2. **Static security analysis.** Retain the fast Python AST lane and add
   CodeQL databases/query packs for supported languages, with Semgrep Pro as an
   independent cross-check when the exact plan and language support are
   enabled. Add interprocedural and cross-file source-to-sink analysis for
   high-impact flows: untrusted input to shell/SQL/template/eval sinks, path and
   archive traversal, unsafe deserialization, SSRF, redirect/TLS bypass,
   credential exposure, authorization checks, and trust-boundary crossings.
   Model aliases, sanitizers, validation dominance, error paths, and framework
   entry points. Report unsupported constructs and parser failures as coverage
   gaps. Keep language-specific rules versioned and reviewable; do not silently
   infer that a function named `validate`, `sanitize`, or `authorize` is safe.
   Model cross-language handoffs explicitly (for example Node/MCP to Python
   through JSON or subprocess arguments). Per-language analysis does not by
   itself prove an end-to-end cross-language flow; require interface contracts
   and runtime challenges for those boundaries.
3. **Dependency and build-chain analysis.** Generate candidate-bound source
   and artifact SBOMs with Syft, scan resolved lockfiles and artifacts with
   OSV-Scanner V2, identify known vulnerable or
   disallowed components, inspect direct and transitive dependencies, and
   validate provenance/signature and build inputs where available. Distinguish
   package metadata from an actually resolved graph; if dependencies cannot be
   resolved offline or from an authorized source, record unavailable coverage.
   Bind reports to tool versions, databases/advisory timestamps, lockfile
   digests, and build environment. No network lookup or provider write should
   occur implicitly in a local audit.
4. **Secrets, configuration, and deployment surfaces.** Scan declared Git
   history with Gitleaks and scan the filesystem/build image with Trivy for
   secrets, misconfiguration, licenses, and vulnerabilities. Inspect CI,
   infrastructure, permission, TLS, and deployment configuration with
   format-aware parsers. Use redacted evidence only. Add
   checks for unsafe defaults, over-broad identity, exposed debug/admin
   surfaces, and secret propagation into logs or artifacts. Keep test fixtures
   and placeholder exceptions explicit, narrow, and mutation-tested.
5. **Dynamic and adversarial behavior.** Add an isolated, disposable
   candidate-specific runtime harness with ZAP Automation Framework for
   authorized API surfaces, Atheris/Jazzer.js harnesses for untrusted parsers,
   and direct tests that exercise declared public and
   privileged entry points. Include negative and boundary cases for
   authentication/authorization, cross-tenant isolation, replay/idempotency,
   input parsing, upload/archive paths, resource exhaustion, and state-changing
   actions. Pair requests with observed effects and denied effects. Use bounded
   fuzz/property inputs and fault injection where the service contract permits.
   Never scan an external target unless a human supplies and confirms the exact
   authorized target and test budget; default runs must stay local and
   non-destructive. A test that did not start, reached the wrong target, or
   could not observe its expected effect is incomplete, not a pass.
6. **Scanner challenge and regression.** For every rule family, keep both
   vulnerable positive fixtures and safe negative fixtures. Mutate or remove
   each detector, source/sink model, authorization guard, coverage check,
   suppression gate, and receipt binding; require the challenge suite to fail
   when the control is hollow. Track killed/attempted mutants, false-positive
   review, parser coverage, and unclassified results separately. A mutation
   suite that only tests example strings is insufficient: fixtures must cover
   syntax variants, aliases, helper boundaries, error handling, and language
   versions the adapter declares supported.
7. **Normalized evidence and specialty AI review.** Normalize findings into
   stable identities bound to candidate digest, location, rule and tool
   versions, reachability/evidence, severity rationale, and status. Preserve
   raw report digests and command/environment metadata. Keep findings distinct
   from analyzer errors, suppressions, accepted risk, and unresolved coverage.
   Suppressions require a named human owner, rationale, exact rule/path scope,
   expiry, and independent approval; expired or widened suppressions block.
   Generate the deep-audit receipt only after all required tools and challenges
   finish, then require the hash-bound specialty AI review described above.
   Keep any eligible human attestation as a separate release-protection gate.
   Receipts never merge, release, deploy, or publish.

### Delivery sequence and acceptance gates

| Stage | Deliverable | Exit criteria |
| --- | --- | --- |
| A. Claim and inventory contract | Versioned scope manifest and coverage states | Every executable target, language, entry point, dependency input, exclusion, and bound is enumerated and candidate-hash-bound; unknown/truncated scope blocks. |
| B. Analysis adapters | Pluggable static, dependency, secret/config, and runtime report producers | Each adapter has a pinned version, schema, timeout/resource bound, explicit failure state, and candidate digest; unsupported input cannot become a clean result. |
| C. Exploit-focused tests | Disposable runtime harness, ZAP API plan, Atheris/Jazzer.js targets, and attack-case catalog | Each high-risk boundary has positive and negative cases, observable expected effects, minimized regressions, and a reproducible seed; no external target is contacted by default. |
| D. Detector assurance | Cross-language positive/negative fixtures and mutation suite | Every required rule and coverage gate has a seeded challenge; removed/inverted rules are caught; results publish attempted/killed counts and exclusions. |
| E. Receipt and policy gate | Extended deep-audit schema and release-policy binding | Candidate, reports, toolchain, scope, suppressions, tests, freshness, and signer identities verify; any missing or stale evidence blocks. Existing review-only authority boundary stays intact. |
| F. Specialty AI review and independent pilot | Read-only specialty AI review contract plus independent human pilot on selected repositories and seeded vulnerable samples | AI reviewer challenges exact candidate-bound findings/coverage and produces a bound report; a second human separately reproduces selected reports, confirms severity and coverage, records misses/noise, and signs exact evidence. AI review does not satisfy human release approval or self-promote the product to a guarantee. |

### Required status model and release criteria

Use separate states for `NOT_RUN`, `INCOMPLETE`, `BLOCKED`, `FINDINGS`, and
`READY_FOR_HUMAN_REVIEW`. “No findings” is a scoped result only. A stronger
review-ready state requires: 100% of the declared required source inventory
accounted for; no required analyzer timeout/error/parser gap; all required
positive and negative challenges completed; zero unresolved critical/high
findings unless a valid scoped risk acceptance explicitly permits them; no
expired suppressions; candidate/report/tool/database bindings verified; and a
fresh specialty AI review report. For protected release, retain a separately
eligible human approval. Publish coverage percentages and excluded
surfaces next to any result, never as a standalone badge. Human release review
remains a separate final gate.

### First implementation slices

1. Extend the current Python-only security receipt with explicit inventory
   completeness, ignored/truncated path accounting, rule-set version, tool
   version, and parser coverage; seed mutations for each existing detector.
2. Add a reviewed language/target inventory and fail closed when source files
   exist outside the selected adapters; specifically add TSX/TypeScript
   parsing coverage before interpreting the existing ForgeLine unsupported
   parser result as assessed.
3. Add one interprocedural source-to-sink family and one authorization-path
   family with multi-file positive/negative fixtures and non-hollow mutations.
4. Add an authorized, local runtime harness for one service entry point and
   bind request/response/effect observations to the candidate receipt.
5. Extend signed deep-audit intake to consume the scanner-produced coverage
   manifest, normalized findings, challenge receipt, exact toolchain
   provenance, and hash-bound specialty AI review report; preserve
   `READY_FOR_HUMAN_REVIEW`, not approval, as the best local result.

Do not expand analyzer scope and lower acceptance thresholds in the same
change. Each slice must include a reproduced blind spot, a failing challenge,
the narrow repair, regression tests, and an independently inspectable receipt.
Until Stages A–F pass for a particular candidate and target, describe the
output as a limited audit, not a penetration test or certification.

## Isolated execution interface (0.46.9)

The repository now implements the execution coordinator and strict evidence
consumer described below. This is **not a completed enterprise scanner product**:
validated native adapter images, real multilingual benchmark results, live
runtime/fuzz coverage and provider marketplace approval remain unproven. The
regression suite uses clearly identified synthetic worker output to test the
coordinator. It must not be cited as a penetration-test receipt.

### Operator sequence

1. Run `factory deep-audit inventory --root <repo> --json`. Every tracked and
   nonignored untracked file contributes bytes, mode, path and language to the
   candidate hash. Deleted, linked, unclassified and ignored product inputs are
   explicit gaps. Move caches outside the audited checkout; do not hide product
   files to obtain a clean inventory. An empty repository is incomplete.
2. Prepare an exact `factory.deep-execution.v1` manifest outside the product
   checkout. It declares distinct implementer/reviewer/coordinator identities and
   signing keys; a pinned local trust root; all six analysis families; immutable
   adapter images; exact tool versions and ruleset hashes; source/requirement
   obligations; positive, negative and disabled-control mutation fixtures. Each
   fixture and expected report has a SHA-256 binding and expected process exit.
   The trust root must explicitly assign each key its role. Generating three
   local keys alone does not establish organizational independence.
3. Have the trusted coordinator sign a fresh
   `factory.deep-execution-authorization.v1` DSSE payload binding the raw manifest
   hash, canonical manifest hash, candidate hash and exact adapter image map.
   Execution documents expire within one hour. All manifest and review inputs
   are explicit operator choices; repository text cannot authorize execution.
4. Provision independently reviewed adapter images and start a **local Linux**
   Docker engine. Images are never automatically pulled. Each image must expose
   `/opt/factory/bin/audit-adapter <engine> --mode <mode>` and contain the approved
   toolchain/rules/offline vulnerability databases. Engine registration does not
   mean an adapter image is supplied or validated by this release.
5. Run the explicit command (replace all placeholders with operator pins):

   ```text
   factory deep-audit scan --root <repo> --manifest <manifest.json> --manifest-sha256 <sha256> --authorization <authorization.dsse.json> --trust-root <trust.json> --trust-root-sha256 <sha256> --events
   ```

   The runner validates authorization before capture and before every lane. It
   snapshots source outside the repository, rechecks hashes, and executes only
   non-root containers with no network, a read-only root and source mount,
   dropped capabilities, resource limits, bounded output and verified cleanup.
   Runtime services and attack harnesses must run **inside that isolated image**;
   arbitrary remote targets and host command fallback are unavailable. Docker
   isolation is not a proof against a hostile host/kernel or same-user tampering.
6. Consume NDJSON events during execution, or read
   `factory deep-audit progress --root <repo> --run-id <id>` and
   `factory deep-audit repairs --root <repo> --run-id <id>` afterward. Findings
   include severity, source hash/path/line, trace where available, repair guidance,
   regression expectations and rerun arguments. Gaps become actionable coverage
   tasks. `cancel` requests bounded worker termination. `scan --resume <id>` starts
   a fresh run of the identical manifest/candidate; it reuses **no** scanner proof.
7. A separate specialty AI reviewer inspects exact source and scanner evidence.
   `factory.deep-specialty-review.v1` includes decision, findings, coverage gaps,
   source/read-set hashes, evidence hash and provider/model/prompt/response
   identifiers. A distinct trusted coordinator signs
   `factory.deep-review-invocation.v1` binding that read-only review invocation.
   Run `factory deep-audit review --root <repo> --run-id <id> --attestation
   <review.dsse.json> --invocation <invocation.dsse.json> --trust-root <trust.json>
   --trust-root-sha256 <sha256>`.

### Adapter evidence contract

The runner mounts `/factory-contract.json` read-only and sets `FACTORY_CONTRACT`,
`FACTORY_RUN_ID` and `FACTORY_CANDIDATE_SHA256`. The contract includes the exact lane,
manifest pin, captured inventory and approved obligations. stdout must contain a
single `factory.deep-worker.v1` JSON object with matching run/candidate IDs and
exactly three named artifacts: native report, `factory.deep-coverage.v1`, and
`factory.deep-challenges.v1`. Diagnostic output belongs on stderr; it is hashed,
not printed. Native bundles are retained locally as potentially sensitive evidence
under ignored `.factory/deep-runs/<id>`; do not commit or upload that directory.

Coverage must bind exact path hashes, report digest, tool/ruleset versions,
invocation digest, obligations, completion and absence of fallback/errors.
Challenge observations must include actual report objects, report and fixture
hashes and exit codes matching the coordinator-approved goldens. A `passed: true`
boolean is insufficient. Goldens are policy-controlled expectations, not proof
that a scanner was executed: native adapter correctness and coordinator trust
still require independent validation. SARIF partial-scan warnings are rejected.
Empty/error-only dependency reports cannot imply a clean resolved dependency scan.
Unsupported native output remains incomplete until a reviewed parser supports it.

### Result and integration boundaries

- Scan completion remains `INCOMPLETE` pending specialty review, even if all
  worker bundles are structurally accepted.
- Review re-normalizes native bundles, verifies signatures/current candidate,
  reconciles reviewer findings and gaps, and can yield `BLOCKED`, `INCOMPLETE` or
  `READY_FOR_HUMAN_REVIEW`. It reports `COORDINATOR_ATTESTED`, without claiming a
  signature from a model provider. High/critical findings block an ACCEPT response.
- Every outcome retains `authority: none` and `release_approval: false`.
- Event-chain checks detect local corruption; self-hashes are not authentication.
  MCP `factory.deep_audit_status` accepts an optional `run_id` to expose progress
  and repairs read-only. Its no-argument behavior is unchanged. MCP does not start
  scanners or sign reviewer evidence.
- Muse keeps `Full-depth penetration: incomplete`; hook inventory/AST passes
  cannot promote it. The hook points to these explicit execution and review
  commands. ForgeLine inventory remains separately reported.
- Repair comparison lists introduced, remaining and disappeared findings. A
  disappeared finding stays pending verification; suppression or a missing
  analyzer never closes a repair.

Remaining production acceptance: ship and independently validate native adapter
images for each supported language/framework, prove extractor/build/runtime
accounting on real positive/negative/mutated targets, validate fresh offline
vulnerability feeds and tool licenses, run cross-platform host checks and the
enterprise benchmark corpus, and obtain a genuine specialty-review invocation
receipt from the separately trusted coordinator. This release does not certify
that arbitrary code is defect-free or supply an organizational security approval.

Native dependency accounting reconciles every declared input with OSV results
and Syft component locations. Obligations bind an engine and detector rule.
Positive challenge reports must contain the native designated detection; negative
fixtures must differ and not detect it. A disabled-detector mutation uses the
positive fixture and must lose that detection. Runtime/fuzz schemas require
candidate-bound harnesses, positive engine metrics and exact line/branch accounting.
These contracts still require validation with real native adapter images.
