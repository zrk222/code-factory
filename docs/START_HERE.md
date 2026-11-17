# Start here: scan, review, repair

Install the core in your existing project. Use your current tests and CI alongside
the scan.

```powershell
python -m pip install factoryline-code-factory
factory scan --root . --static-only
```

| Choose this when you want to… | Run |
| --- | --- |
| Quickly review Python source without running the project | `factory scan --root . --static-only` |
| See all applicable local evidence lanes and what is missing | `factory scan --root .` |
| Review findings visually | `factory studio --root .` |
| Get command guidance | `factory --help` or `factory scan --help` |

`--deep` explicitly selects the default mode. Deep scan includes available
architecture, security, test-oracle, workflow, requirements, runtime, and
dependency evidence. It inventories other languages, but native analysis
requires configured workers. Missing checks stay **INCOMPLETE**. Static results
do not prove that behavior was tested at runtime.

The default Python budget is 2,000 files. Use `--max-files 1000` to set a
smaller limit; an over-budget scan stops and reports the gap. Fix findings, run
your existing tests, then rerun the affected checks. Reports show file locations
and audited/discovered counts.

## CI/CD integration: what is supported

```powershell
factory scan --root . --json > factory-scan.json
```

Retain the JSON output. Exit **0** means no blocking finding or failed check,
and can still include advisories or incomplete evidence. Exit **2** means blocked
or invalid analysis. Add `--require-complete` to require both `state` and
`verdict` to be `PASS`.

Use the maintained [GitHub Proof Review](GITHUB_PROOF_REVIEW.md) integration for
review comments and [signed receipts](SIGNED_RECEIPTS.md) for verified CI
evidence. Other CI providers can invoke the CLI and retain the JSON as an artifact.

## Optional workflows

- **See the evidence flow in a sandbox:** `factory first-proof --root .` runs a
  positive and negative control and writes a local receipt. See the
  [first-use guide](FIRST_USE.md) for that flow and for adopting an existing repo.
- **Start a new product:** [Build a starter or clarify a PRD](APP_BUILDER.md).
- **Review a change:** [Use the proof workflow](PROOF_REVIEW_WORKFLOW.md).
- **Run configured native checks:** pass `--worker-config .factory/worker-config.json`.
  See [worker setup](../deploy/deep-adapters/README.md) and
  [runtime assurance](RUNTIME_ASSURANCE.md). Runtime plans require their own
  reviewed inputs and evidence.
- **Manage approvals and signed evidence:** see
  [enterprise operations](ENTERPRISE_OPERATIONS.md).

### Install the full toolchain

The core wheel installs the scanner and coordinator. For Core 0.49.7, install
the published SpecLine, ForgeLine, HSF, and Prestige wheels in the same Python
3.11+ environment:

```powershell
python -m pip install factoryline-code-factory==0.49.7 code-factory-1-spec==0.5.4 code-factory-2-forge==0.10.8 code-factory-3-compile==0.5.5 code-factory-4-design==0.8.0
factory doctor --strict --json
```

The distribution names differ from their commands: `specline`, `forge`, `hsf`,
and `prestige`. The core scan does not require those packages. For a source
build of this repository, `python -m pip install ".[factory]"` selects the same
companion versions.

`factory doctor --strict --json` checks setup. `factory --help-all` lists advanced
commands. In interactive terminals an optional version notice uses a daily PyPI
check; set `FACTORY_DISABLE_UPDATE_CHECK=1` to disable it.

<details>
<summary>Experimental Jev evidence review and feedback</summary>

## Experimental Jev evidence review

The optional Node.js trial runner compares a frozen labelled corpus with
`typesafe-ai/jev` through Vercel AI Gateway. It evaluates defect support and
evidence sufficiency separately. It can review a CF finding or compare a report
with raw source and execution observations. Expected labels are not sent to the
model; missing evidence, uncertain answers and transport failures stay unresolved.

From a source checkout, prepare cases as a JSON array of
`{id, category, expected, state}` records. `state` can contain `requirement`,
`candidate`, `evidence` and `cf_output`. The packaged judging framework defines
the evidence and evaluation protocol:

```powershell
node scripts/evaluate_jev.mjs --cases cases.json --rubric factoryline/data/judge_framework.json --out trial-dry-run.json
```

This defaults to no network and reports `NOT_RUN`. Add `--live` only when you
intend to transmit the supplied evidence and have configured
`AI_GATEWAY_API_KEY`. Live calls request zero data retention and restrict the
provider to TypeSafe AI. The runner records costs only when the provider reports
them; it cannot independently verify provider retention or immutable model weights.

Freeze development and holdout cases separately, retain disagreements, and
compare precision, recall, abstentions and coverage by audit category. Confidence
is not correctness. The trial cannot override scanner findings, approve a release
or establish production accuracy. The wheel includes the runner under
`share/code-factory/evaluation` and the framework in `factoryline/data`.

For advisory criterion grading, use `--grade`. Each case must ask whether one
explicit violation exists: an admitted false answer passes that criterion and
an admitted true answer fails it. The summary uses equal weights and ignores
expected evaluation labels. Any unresolved criterion keeps the final score
`null`; its possible score interval is not an achieved grade. This does not
replace CF's deterministic quality grade, security blockers or release policy.
The same report includes an **Experimental Jev score**: the equal-weight mean
of `100 * (1 - finding probability)` for the supplied criteria. It can display
even when evidence admission abstains. This is an uncalibrated model assessment,
not detection accuracy or an evidence-validated grade. Missing model responses
leave the complete score `null`; any observed mean and response coverage remain
explicitly partial. Evidence probabilities and admitted decisions stay separate.
Every CLI trial also writes a local journal under `.factory/jev/evaluations`.
It reserves storage before contacting the provider, flushes each normalized
answer or error before the next request, and stores the final report with hashes.
Run IDs link scores, evidence probabilities, abstentions, latency and cost for
later validation. Raw state and API keys are not copied into the journal.
Interrupted runs retain partial results; storage failures stop further requests.
The hash chain detects changed records relative to a retained original; a local
writer can still replace the entire journal. Journals remain until you remove
them. The `evaluateCases` library API returns reports to its host; hosts must
persist them or provide its awaited `onResult` callback for checkpointing.
Journal directories must stay under the selected workspace and cannot traverse
linked directory components. Unix archive permissions are restricted to the
owner; Windows archives inherit the workspace's account ACL. A process with
write access to the workspace can still tamper with local records.
Validate a recorded run offline with
`node scripts/evaluate_jev.mjs --verify-journal .factory/jev/evaluations/<run-id>.jsonl`.
The verifier checks chained hashes, result order/uniqueness and final report
bindings; incomplete histories exit with an incomplete result. Integrity does
not establish judgment accuracy. Integrators can supply an independently
retained SHA-256 through `verifyJournal(path, { expectedJournalSha256 })` to
detect replacement of the complete local chain.

### Operator feedback for Jev validation

Record corrections offline with `--record-feedback <journal.jsonl> <feedback.json>`.
Each new record under `.factory/jev/feedback` binds the complete verified run,
case and result hashes. Earlier judgments and annotations remain intact.
Feedback must contain exactly these fields:

```json
{
  "case_id": "case-1",
  "operator_sha256": "<64-character lowercase pseudonymous operator digest>",
  "disposition": "corrected",
  "corrected_finding": false,
  "reason": "false_positive",
  "evidence_sha256": "<64-character lowercase supporting-evidence digest>"
}
```

Dispositions are `confirmed`, `corrected` or `unresolved`; unresolved verdicts
use `null`. Reasons are `correct_finding`, `false_positive`, `false_negative`,
`missing_evidence`, `scope_mismatch`, `transport_failure` or `uncertain`.
False-positive and false-negative reasons must oppose an original admitted
prediction; an abstention cannot be labelled as either. Corrections to unresolved
results use an evidence or uncertainty reason. A confirmed annotation must match
the original admitted prediction, and a correction must change it.
Use digests rather than names, emails, source excerpts or credentials. Evidence
digests identify retained evidence; the recorder does not verify its meaning or
authenticate the operator. Independently adjudicate annotations before using
them as calibration labels. Feedback never automatically changes a scanner
verdict, tunes thresholds, or proves detection accuracy.
See the framework's `grading_protocol` for evidence scope, host provenance
checks, calibration and bias controls. Loading the framework is not proof that
its entire calibration protocol has been executed.

### PRD and PR review profiles

Use the packaged framework with `--profile prd` for document requirements or
`--profile pr` for a changed-code review. Both remain experimental and offline
by default:

```powershell
node scripts/evaluate_jev.mjs --cases prd-cases.json --rubric factoryline/data/judge_framework.json --profile prd --grade --out prd-review.json
node scripts/evaluate_jev.mjs --cases pr-cases.json --rubric factoryline/data/judge_framework.json --profile pr --grade --out pr-review.json
```

Supply one observable criterion per case. PRD evidence includes the document
revision, excerpt and location; PR evidence includes the requirement, bound diff,
affected contracts and relevant execution observations. Expected labels are
development evaluation annotations, withheld from the provider, and never used
to award grades. These profiles select rubrics; they do not automatically fetch
private documents or repositories, run tests, comment on a PR or grant approval.

Repeated scans in the same Python process reuse source-bound oracle context.
This local cache expires after five minutes and is limited to 16 entries and
4 MiB. Every scan still reads and verifies current sources and recomputes
findings; it does not reuse verdicts. Separate CLI processes do not share it.
Python callers can pass `cache_enabled=False` to `security_scan` for comparison.

The factory optimizes for a small, fact-derived next action, reuse of verified
read-only proof, and less reconstruction of context. It does not claim time,
token, cost, productivity, conversion, security certification, or production
readiness without a corresponding measured or hash-bound receipt.

</details>
