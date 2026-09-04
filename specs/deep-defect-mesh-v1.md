# Spec: Deep Defect Mesh v1
Status: draft
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description
Code Factory shall turn bounded SARIF 2.1.0 reports from independent static,
data-flow, memory, concurrency, correctness, and maintainability analyzers into
one deterministic, actionable review receipt. The feature detects introduced
findings, incomplete nested traces, analyzer/configuration failure, hidden
suppressions, missing negative controls, and correlated cross-analyzer risk.
It does not claim that a clean report proves defect absence.

### User roles
- A named human or trusted policy owner signs the rule and analyzer contract.
- A supervised coding agent may produce candidate code and analyzer artifacts.
- A reviewer reads the resulting receipt and retains release authority.

### Requirements (EARS)
- When `REQ_PLAN` accepts input, it shall accept exactly 1 externally signed `factory.deep-audit-plan.v1` DSSE envelope, exactly 1 separately SHA-256-pinned trust-root file, 1 to 8 signed analyzer declarations, 1 to 256 signed rule contracts, 1 to 128 signed canary contracts, and 1 to 128 hash-bound candidate source files. [R10]
- When `REQ_VERIFY` inspects the plan, it shall verify Ed25519 signature trust, an aware issuance time, an expiry no more than 24 hours after issuance, current non-expiry, exact candidate source hashes and byte sizes, a candidate manifest digest, unique identifiers, exact fields, bounded values, and authoritative rule origins from `human_confirmed` or `trusted_source`; production observations and agent proposals shall not authorize gates. [R20]
- When `REQ_SARIF` evaluates analyzer evidence, it shall accept 1 to 8 workspace-local non-symlink SARIF 2.1.0 files of at most 10,000,000 bytes each and reject duplicate JSON fields, absolute or escaping paths, failed or missing invocation status, an unexpected driver/version, duplicate tool identities, more than 20,000 findings, or unsupported severity/baseline/suppression values. [R30]
- When `REQ_RULE` matches a SARIF result to a signed rule contract, it shall compute the blocking decision only from the signed obligation, category, exact rule aliases, maximum introduced and total counts, minimum nested trace depth from 0 to 128, required source/sink roles, suppression allowlist, and remediation. [R40]
- If `REQ_BLOCK` observes an introduced error with no signed rule mapping, a finding with an unapproved suppression, a required nested code-flow that is too shallow or lacks source/sink roles, a signed threshold that is exceeded, or a required analyzer that did not complete, it shall return `BLOCKED` with a closed finding code and an ordered remediation item. [R50]
- When `REQ_CANARY` checks 1 to 128 negative controls, it shall require every signed canary fingerprint and rule alias to appear in 1 separate workspace-local canary SARIF file no larger than 10,000,000 bytes from the declared analyzer; 1 or more missing canaries shall return `HOLLOW_DEEP_AUDIT`. [R60]
- When `REQ_CLUSTER` observes multiple analyzers reporting the same signed obligation on the same workspace path, it shall emit a deterministic corroboration cluster; when two or more categories occur on the same path, it shall emit a compound-risk cluster; these clusters shall be labelled routing signals and shall not be represented as proof of causation. [R70]
- When `REQ_RECEIPT` completes an audit, it shall write exactly 1 canonical, self-hashed `factory.deep-audit-receipt.v1` containing exact input hashes, 0 to 20,000 normalized findings, analyzer completion, trace depth, suppression state, 0 to 20,000 clusters, a 0 to 20,000 item severity-then-path-then-rule ordered repair queue, decision `BLOCKED` or `READY_FOR_HUMAN_REVIEW`, authority `none`, and explicit scope limitations. [R80]
- When `REQ_SURFACE` receives an agent or IDE status request, it shall expose the latest self-hash-verified receipt through CLI, MCP, Mission Control, and the IDE playbook without executing analyzers, modifying code, approving, merging, publishing, or deploying. [R90]
- When `REQ_WINDOWS` inspects evidence on Windows, it shall return the same canonical decision facts without invoking 1 shell wrapper, 1 hosted service, 1 network request, or 1 analyzer executable. [R100]
- When `REQ_GRAPH` projects a receipt, it shall emit at most 50 finding subgraphs linking source, approved obligation, finding, evidence, decision and repair handoff, label truncation explicitly, and retain the complete receipt reference. [R110]
- When `REQ_LOOP` compares exactly 2 hash-valid audit receipts, it shall reject a changed signed ruleset or canary set, detect new finding identities and missing analyzer evidence, return `regressed` for new findings, `stagnated` for no reduction, `repair_required` for a strict reduction with findings remaining, or `approval_required` only when the new receipt is READY_FOR_HUMAN_REVIEW with zero blocking repairs; it shall grant zero execution or approval authority. [R120]
- When `REQ_FINGERPRINT` normalizes a finding, it shall require 1 to 16 native SARIF fingerprint fields, derive 1 versioned finding identity from analyzer, rule alias and native fingerprints rather than line numbers, bind every location to 1 signed source hash, and emit exact report, normalized report, ruleset, ordered trace, and receipt SHA-256 digests; missing fingerprints or unbound flow locations shall block rather than fabricate continuity. [R130]

## Claim boundary
The receipt treats a SARIF report as analyzer evidence rather than truth; an
absent finding is not proof of absence. Corroboration raises review priority
without proving exploitability, causation, or defect severity. Analyzer
execution, build capture, runtime sanitizers, fuzzers, and release approval are
outside this evidence-normalization gate.

## Acceptance criteria (Gherkin)

```gherkin
Scenario: Signed nested issue is blocked with an actionable trace
  Given REQ_PLAN and REQ_VERIFY accept 2 completed declared analyzers and 1 introduced signed rule with minimum trace depth 4
  And the result contains a 5-step source-to-sink SARIF code flow
  When REQ_SARIF and REQ_RULE evaluate the supplied evidence
  Then REQ_BLOCK returns BLOCKED because the signed introduced threshold is exceeded
  And the repair queue names the obligation, primary path, rule, consequence and remediation

Scenario: Hollow analyzer configuration fails closed
  Given REQ_CANARY receives a signed canary contract naming 1 exact analyzer, rule alias and fingerprint
  When REQ_CANARY reads a canary SARIF that does not contain that fingerprint
  Then REQ_BLOCK returns BLOCKED with HOLLOW_DEEP_AUDIT

Scenario: Clean bounded evidence remains human-reviewed
  Given REQ_SARIF observes every required analyzer completed and REQ_CANARY detects every signed canary
  And no signed threshold, nested trace, suppression or unknown introduced-error rule failed
  When REQ_RECEIPT evaluates the supplied evidence
  Then REQ_RECEIPT returns READY_FOR_HUMAN_REVIEW
  And release approval remains false

Scenario: Correlated findings are deterministic routing signals
  Given 2 analyzers report the same obligation and path
  And 2 signed categories occur on that path
  When REQ_CLUSTER builds clusters
  Then REQ_CLUSTER emits 1 corroboration cluster and 1 compound-risk cluster
  And it states that neither cluster proves causation

Scenario: Read-only Windows surfaces preserve authority
  Given REQ_RECEIPT wrote 1 self-hash-verified receipt
  When REQ_WINDOWS inspects it and REQ_SURFACE exposes it to an IDE
  Then REQ_SURFACE returns the same decision without executing an analyzer or granting release authority

Scenario: Findings stay connected to the repair loop
  Given REQ_RECEIPT contains 1 blocked finding and its signed obligation
  When REQ_GRAPH projects it and REQ_LOOP compares a fresh second receipt
  Then REQ_GRAPH links the source through evidence to a repair handoff
  And REQ_LOOP returns stagnated if the blocking finding has not decreased

Scenario: A moved finding retains its native identity
  Given REQ_FINGERPRINT receives the same analyzer, rule alias and native fingerprint at a different signed source line
  When REQ_FINGERPRINT derives the finding identity and ordered trace digest
  Then the finding identity remains equal while the changed trace digest differs
```

## SHOULD - Technical/structural
- Ingestion v1 limits each source to 10,000,000 bytes, each report to 1 run, each result to 10 primary locations and 128 total ordered flow steps; code-flow and thread-flow arrays each allow at most 16 entries. It accepts at most 16 invocations and 128 notifications per invocation category. UTF-8 canonical JSON rejects non-finite values. Collection limits are resource-safety bounds, not defect thresholds.
- Timestamp text permits at most 40 characters and maps ISO-8601 Z to +00:00. Paths, rule IDs/obligations and remediation/consequence text permit at most 512 characters; native fingerprint values permit at most 1024 characters. Fingerprint names permit at most 128 characters. These are parser resource limits, not authority granted by prose.
- Source paths use canonical relative slashes without URI encoding, base references, Windows reserved names or reparse points. Report and canary paths and hashes must be distinct. A signed canary is required for each declared analyzer.
- Contract fields and parser subset are documented in docs/DEEP_AUDIT_INGESTION.md; this slice does not yet implement the decision evaluator or external scanner execution.
- Reuse strict JSON, canonical hashing, path, and receipt primitives from Runtime Assurance.
- Preserve existing Qodana/SonarQube evidence behavior and add the deep mesh as a separate contract.
- Prefer CodeQL path evidence, Semgrep taint evidence, Infer interprocedural findings, Clang sanitizer/static-analysis evidence, Qodana, SonarQube, and other SARIF producers as external engines; never reimplement their analyzers.

## SHOULD NOT - Implementation details
- Do not infer blocking severity from prose, model output, filenames, or rule names.
- Do not auto-fix source, upload SARIF, execute an analyzer, or weaken a signed threshold.
