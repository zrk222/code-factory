# Recall and precision evidence

The advisory verifier preserves strict hunk recall as the primary historical
measurement. It credits an old-side detection inside a fix hunk. This measures
localization to a maintainer's change. A related detection can instead point to
a call site, dataflow step, or library sink elsewhere.

Use the separate advisory-linked result for those findings. Keep its lane,
scan scope, ecosystem, and denominator visible. A configured language worker
shows availability. Claims about detection accuracy need measured evidence
for that lane and ecosystem.

## Signer and execution evidence

The precision scorer accepts an optional provenance bundle for a frozen
single-arm sample. The bundle holds one execution envelope and two label
envelopes. Supply a trust root and its SHA-256 from an independently approved
source.

```powershell
python scripts/verify_precision_gain.py sample.json --out receipt.json --summary `
  --provenance statements.json --trust-root trust.json --trust-root-sha256 $approvedPin
```

The bundle uses schema `factory.benchmark-provenance.v1` with an
`execution` envelope and two ordered `reviewers` envelopes. Use the
existing Code Factory DSSE format with payload type
`application/vnd.factory.benchmark-evidence-statement.v1+json`. The execution
statement for a precision sample binds the selected observation bytes.

```json
{
  "schema": "factory.benchmark-evidence-statement.v1",
  "purpose": "precision-execution",
  "subject_sha256": "<SHA-256 of the exact selection document bytes>"
}
```

The execution signer needs the `benchmark-execution` role. Each
`precision-labels` statement covers the exact bytes of one reviewer document
in contract order. Its signer needs `benchmark-review` and an identity matching
that document. All three signers need distinct identities and key material.

The verifier authenticates who made each claim and checks the attached bytes.
Execution honesty, reviewer independence, blindness, and the quality of a
review require evidence from the collection and review procedures. Model
reviewers can share biases even when their signatures authenticate separately.
Legacy scores report `UNATTESTED`. Signed scores keep review independence
`UNESTABLISHED` and confer no publication approval.

## Advisory-linked results

Run the advisory scorer with the legacy record and a separate signed capture.
The strict summary stays keyed to the existing fix hunks.

```powershell
python scripts/verify_precision_gain.py advisory-recall recall.json `
  --linked-observations captures.json --link-review reviewer-one.json `
  --link-review reviewer-two.json --provenance statements.json `
  --trust-root trust.json --trust-root-sha256 $approvedPin
```

- The capture document uses schema `factory.advisory-link-observations.v1`.
  Include `record_sha256` for the exact legacy document,
  `candidate_sha256` for the canonical JSON of its candidate object, and
  `rows` keyed by `ghsa`, `lane` (`pattern` or `codeql`), and `scope`
  (`changed_files` or `repository`).
- Each row identifies the first pre-fix commit in `source_revision` and a
  `state` of `complete` or `unknown`. For a complete row include the
  `source_tree_sha256` and a `capture` object with `path` and `sha256` for
  a SARIF 2.1.0 report. Use paths relative to the capture document and
  repository-relative finding URIs. Each SARIF run must record successful
  execution. The `advisory-execution` statement covers the exact capture
  document bytes.
- Each reviewer uses schema `factory.advisory-link-labels.v1` with
  `reviewer_id`, `observations_sha256`, and `labels` for every complete row.
  Use the same three row keys and a `verdict` of `linked`, `no_link`, or
  `unclear`. A linked verdict cites a unique emitted `finding` by
  `path`, `rule`, `line`, and any emitted `column`, `end_line`, and
  `end_column`. Each `advisory-link-labels` statement covers its exact
  reviewer document bytes.

Both authenticated reviewers must identify the same finding to credit a link.
The result counts links outside the hunk and outside changed files separately.
An unresolved review, a missing capture, and a reviewed no-link verdict remain
separate outcomes. The result retains all registered advisories in each
declared lane and scope. Legacy records have no such captures and report
`NOT_MEASURED` for advisory-linked recall.
