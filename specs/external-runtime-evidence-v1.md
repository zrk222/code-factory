# Spec: external-runtime-evidence-v1
Status: draft
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Provide a local, provider-neutral import boundary for runtime-test results produced
by TestSprite or another user-selected runner. The feature normalizes one small,
hash-bound external evidence bundle, exposes it in read-only Graph Ops, and
compares two imported runs deterministically. It helps a developer connect live
runtime feedback to Code Factory proof debt without making the external runner a
release authority or uploading source.

### User roles
- Developer: imports and compares their own runner output.
- Reviewer: inspects external evidence, freshness, and unresolved hypotheses.
- Code Factory: validates the envelope and projects facts; it never authenticates
  a provider or grants execution/release authority.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- The system shall reject any bundle that is not a workspace-contained JSON `REQ_EXT_BUNDLE_SHAPE`
  object with the exact `factory.external-runtime-bundle.v1` shape and a
  supported provider id.
- The system shall store a normalized provider, project id, test id, run id, `REQ_EXT_NORMALIZED_FACTS`
  snapshot id, code version, environment fingerprint, verdict, failure kind,
  first failed step, hypothesis, recommended fix, and artifact-reference set.
- The system shall verify every referenced artifact path remains below the `REQ_EXT_ARTIFACT_HASH`
  workspace and its bytes match the declared SHA-256 before writing a receipt.
- When the provider is `REQ_EXT_TESTSPRITE_BOUNDARY`, the system shall emit the supplied `testsprite`
  run/test/snapshot identifiers and shall not invoke TestSprite, fetch
  credentials, or infer facts from a dashboard.
- When an imported receipt is written, the system shall record the source bundle `REQ_EXT_RECEIPT_AUTHORITY`
  digest, normalized facts, freshness boundary, and an authority map with release,
  merge, repair, deployment, signing, messaging, credential, and connector set
  to false.
- When two receipts are compared, the system shall emit verdict, failure-kind, `REQ_EXT_DIFF_DELTAS`
  first-step, code-version, environment, and artifact deltas; mismatched provider,
  project, or test identity shall produce an incomparable result and non-zero CLI status.
- If the bundle is malformed, stale, outside the workspace, or has mismatched artifact bytes, the system shall reject the import without writing a receipt `REQ_EXT_FAIL_CLOSED`.
- If the bundle is over 1048576 bytes or an artifact is over 1048576 bytes, the system shall reject the import with `REQ_EXT_SIZE_BOUND` without writing a receipt `EXTERNAL_EVIDENCE_SIZE_LIMIT`.
- The system shall store imported receipts below `REQ_EXT_RECEIPT_LOCATION` `.factory/external-evidence/`.
- The system shall emit imported receipt facts through `factory graph ops --json` without executing a provider or changing release authority `REQ_EXT_GRAPH_PROJECTION`.
- While Graph Ops reads imported receipts, Graph Ops shall emit a `REQ_EXT_GRAPH_NODE`
  node with `external_runtime` and `observed_external` status, keep hypotheses in a
  separate field from verified facts, and never use that node to authorize a
  release or automatic repair.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: import a valid TestSprite-shaped bundle
  Given a workspace-contained external bundle and matching artifact hashes
  When `factory external import` is run with provider `testsprite`
  Then one `factory.external-runtime-receipt.v1` receipt is written with the
       source digest, snapshot id, observed verdict, and all release authority false
  And `REQ_EXT_BUNDLE_SHAPE`
  And `REQ_EXT_NORMALIZED_FACTS`
  And `REQ_EXT_ARTIFACT_HASH`
  And `REQ_EXT_TESTSPRITE_BOUNDARY`
  And `REQ_EXT_RECEIPT_AUTHORITY`

Scenario: reject a tampered artifact
  Given a bundle whose artifact SHA-256 does not match the current file
  When the import command runs
  Then it exits non-zero with `EXTERNAL_EVIDENCE_ARTIFACT_STALE` and writes no receipt
  And `REQ_EXT_FAIL_CLOSED`
  And `REQ_EXT_SIZE_BOUND`

Scenario: compare two compatible runs
  Given two receipts for the same provider and test id with different run ids
  When `factory external diff` is run
  Then it reports verdict transition, first divergent step, failure-kind change,
       code-version change, and artifact additions/removals
  And `REQ_EXT_DIFF_DELTAS`

Scenario: refuse a cross-test comparison
  Given two receipts with different test ids
  When `factory external diff` is run
  Then it reports `EXTERNAL_DIFF_INCOMPARABLE` and exits non-zero

Scenario: project external evidence safely
  Given a valid imported receipt
  When `factory graph ops --json` is run
  Then Graph Ops contains an `external_runtime` node and an external-evidence count
       while the recommendation and authority remain local and read-only
  And `REQ_EXT_GRAPH_PROJECTION`
  And `REQ_EXT_RECEIPT_LOCATION`
  And `REQ_EXT_GRAPH_NODE`
```

## SHOULD — Technical/structural
- ADR references: `adr/0013-receipt-backed-graph-runtime.md`,
  `adr/0012-governed-instruction-learning.md` (external systems remain evidence
  sources, not governors).
- Data model: `factory.external-runtime-bundle.v1` input and
  `factory.external-runtime-receipt.v1` output; imported receipts live below
  `.factory/external-evidence/` and are content-addressed by source bytes.
  Limits are 1 MiB per bundle and 1 MiB per referenced artifact. Supported
  commands are `factory external import` and `factory external diff`; stable
  markers are `EXTERNAL_EVIDENCE_IMPORTED`, `EXTERNAL_EVIDENCE_ARTIFACT_STALE`,
  `EXTERNAL_DIFF_COMPARABLE`, `EXTERNAL_DIFF_INCOMPARABLE`, and
  `GRAPH_OPS_EXTERNAL_RUNTIME_READ_ONLY`.
- API contract: local Python functions
  `import_external_runtime_bundle(root, bundle, provider, out)` and
  `diff_external_runtime_receipts(root, left, right)` and
  `verify_external_runtime_receipt(root, receipt)`; CLI is offline and
  side-effect limited to the explicit receipt output.
- Safety invariants: bounded JSON/artifact sizes, workspace-relative paths,
  no network/process invocation, no credentials, no source retention, exact
  identity matching for comparisons, and immutable/idempotent output.

## SHOULD NOT — Implementation details
<!-- Leave the "how" to the plan/tasks unless it is a systemic invariant -->

## Declared decision facts
- `bundle_valid`: exact schema and required fields pass.
- `artifact_valid`: every artifact exists below root and matches its SHA-256.
- `imported_receipt`: a normalized receipt was written idempotently.
- `identity_comparable`: provider, project id, and test id match for both diff inputs and run ids differ.
- `external_evidence_present`: Graph Ops found at least one valid imported receipt.

## Decision logic (factory candidates)
<!-- Ordered business rules over extracted facts. specline handoff compiles
     these via HSF instead of letting agents improvise them. -->
| # | if | then |
|---|----|------|
| 1 | `bundle_valid` is false | reject with stable input error; do not write |
| 2 | `artifact_valid` is false because bytes differ | reject with `EXTERNAL_EVIDENCE_ARTIFACT_STALE` |
| 3 | `artifact_valid` is false because a path is missing or invalid | reject with `EXTERNAL_EVIDENCE_ARTIFACT_INVALID` |
| 4 | `bundle_valid` and `artifact_valid` are true | set `imported_receipt` and write a receipt marked `observed_external` with authority false |
| 5 | `identity_comparable` is false | return `EXTERNAL_DIFF_INCOMPARABLE` and non-zero status |
| 6 | `identity_comparable` is true | return deterministic deltas and `EXTERNAL_DIFF_COMPARABLE` |
| 7 | `external_evidence_present` is true | project read-only external runtime evidence; do not change release recommendation authority |
