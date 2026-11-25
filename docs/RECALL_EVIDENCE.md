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

Package saved OpenGrep outputs before review. Run the collector against a local
plan containing paths relative to the plan directory.

```sh
python scripts/verify_precision_gain.py prepare-linked-captures capture-plan.json
```

Use schema `factory.advisory-capture-plan.v1` with `record`, `opengrep`, and
`ruleset` paths, plus `registered_scopes` and `rows` as described below. A
complete pattern row supplies `source_root`, `native_report`, and `sarif` paths.
For the native report and SARIF, pass the scanner's `{path, sha256}` reference
when available so preparation verifies the fingerprints recorded during scanning.
For harness captures with work-directory-relative paths, place the plan in that
work directory or make each path relative to the plan.
To collect a saved `score` or `evaluate` result, place it in the same work
directory and set `score_result` to its `{path, sha256}` reference in the plan.
For complete pattern rows, supply the advisory ID, source revision, and
`changed_files` scope. The collector takes the candidate's saved old-side path
and report references, verifies the scan diagnostics and source packets, and
binds the exact score receipt in the prepared observations.
The scan must record the SHA-256 of its OpenGrep executable. Regenerate saved
receipts that lack this fingerprint.
Saved score receipts have a 32 MB byte budget.
Declare CodeQL scopes that still await capture and use `unknown` for any row
without a complete observation. The collector reads local files, verifies the
candidate pins and source snapshot, and writes a content-addressed observations
file beside the plan. Its SHA-256 is the execution statement subject. Reviewers
use that same hash for their labels. Preparation leaves the capture unattested.

Run the advisory scorer with the legacy record and a separate signed capture.
The strict summary stays keyed to the existing fix hunks.

```powershell
python scripts/verify_precision_gain.py advisory-recall recall.json `
  --linked-observations captures.json --link-review reviewer-one.json `
  --link-review reviewer-two.json --provenance statements.json `
  --trust-root trust.json --trust-root-sha256 $approvedPin
```

- The capture document uses schema `factory.advisory-link-observations.v1`.
  Include `record_sha256` for the exact legacy document and
  `candidate_sha256` for the canonical JSON of its candidate object. Declare
  `registered_scopes` as the list of lane and scope pairs. Each pair contains
  `lane` (`pattern` or `codeql`) and `scope` (`changed_files` or `repository`).
  Keep unexecuted pairs in that declaration.
- Include `rows` keyed by `ghsa`, `lane`, `scope`, and `source_revision`.
  Use a registered pre-fix commit and a `state` of `complete` or `unknown`.
  A complete row has a local `source_root` relative to the capture document.
  Set `source_tree_sha256` to the SHA-256 of the canonical JSON object mapping
  each repository-relative file path to its SHA-256. The verifier enumerates
  the snapshot, hashes its files, and checks the legacy pre-fix file pins.
- Include the `capture` and `coverage` references as objects with `path` and
  `sha256`. The capture is a SARIF 2.1.0 report with successful invocations
  and repository-relative finding URIs. The coverage document uses schema
  `factory.advisory-engine-coverage.v1` and binds `source_revision`,
  `source_tree_sha256`, `sarif_sha256`, `engine_sha256`, and
  `configuration_sha256` to the same row and candidate. It reports
  `expected_paths`, `scanned_paths`, `skipped`, and `errors`. For complete
  observations, the expected and scanned path lists equal the local
  snapshot and both diagnostic lists are empty. For the pattern lane,
  `native_report` references the original engine JSON by `path` and `sha256`.
  Emit JSON and SARIF from the same invocation with scanned and skipped paths
  enabled. The verifier checks the original path inventory and diagnostics
  against the snapshot and the exact rule IDs, spans, and multiplicities against
  SARIF. The execution collector supplies these files from its scanner run. Its
  `advisory-execution` statement covers the exact capture document bytes.
- Each reviewer uses schema `factory.advisory-link-labels.v1` with
  `reviewer_id`, `observations_sha256`, and `labels` for every complete row.
  Use the same four row keys and a `verdict` of `linked`, `no_link`, or
  `unclear`. A linked verdict cites a unique emitted `finding` by
  `path`, `rule`, `line`, and any emitted `column`, `end_line`, and
  `end_column`. Each `advisory-link-labels` statement covers its exact
  reviewer document bytes.

Both authenticated reviewers must identify the same finding to credit a link.
The result counts links outside the hunk and outside changed files separately.
An unresolved review, a missing capture, and a reviewed no-link verdict remain
separate outcomes. A no-link verdict requires all registered revisions for that
case and scope. Each lane and scope reports the registered advisory families
and ecosystems. An advisory can appear in multiple families, while cases with
no mapped family appear under `unclassified`. The result retains all registered
advisories in each declared lane and scope, counts each linked advisory once in
the combined result, and
reports overlap between lanes. Legacy records report `NOT_MEASURED` for
advisory-linked recall.
