# Three complementary checks, not one green test

Your tests pass. That leaves two other questions unanswered:

1. **Test sensitivity:** Would the check notice a broken implementation? CF's existing hollow-test and mutation checks challenge that.
2. **Pattern consistency:** Does this implementation omit a guard or reliability call required for its peers? The new pattern audit shows the difference and peer evidence.
3. **Guard-path ordering:** Is the guard on every analyzed branch before a sensitive operation? The new guard-path audit produces a branch witness when call presence alone hides a bypass.

These checks complement code review. None proves the application correct.

## A bug a call search would miss

```python
def safe():
    require_auth()
    store.delete()

def candidate():
    if permitted:
        require_auth()
    store.delete()
```

Both functions contain `require_auth` and `store.delete`. The pattern audit finds no missing call. The guard-path audit points to the false branch: the delete operation has no preceding guard statement on that structural path. A reviewer decides whether that branch is feasible and whether the declared guard enforces the intended rule.

If `candidate` omits `require_auth` entirely, the pattern audit also shows which peer contains it. If all peers omit it, the required-call finding remains; majority agreement never becomes correctness.

## Set up a reviewed policy

Save the Python example above as `app.py`, then save this policy as `.factory/review-audits.json`. For real use, choose sensitive operations, peer functions and required guards with a human reviewer. Start with one security-critical flow rather than a long generated checklist.

```json
{
  "schema": "factory.review-audit-policy.v1",
  "pattern_groups": [
    {
      "id": "peer-guards",
      "origin": "agent_proposed",
      "members": [
        {"path": "app.py", "symbol": "safe"},
        {"path": "app.py", "symbol": "candidate"}
      ],
      "required_calls": ["require_auth", "store.delete"]
    }
  ],
  "effect_rules": [
    {
      "id": "delete-guard",
      "origin": "agent_proposed",
      "target": {"path": "app.py", "symbol": "candidate"},
      "guard_call": "require_auth",
      "effect_call": "store.delete"
    }
  ]
}
```

`origin` records a declaration, not an authenticated signature. Changing it to `human_confirmed` does not grant authority. To use findings in a release gate, bind the reviewed policy digest through your existing approved intent/Oracle Firewall process. These tools cannot approve or release anything.

## Run the audits

```sh
factory audit patterns --json
factory audit guard-paths --json
factory audit all --json
factory change review --changed app.py --out-dir .factory/reviews --json
```

Individual audit commands return exit 0 only for `no_structural_findings` within their declared scope. Findings, incomplete analysis and invalid inputs return exit 2. An `all` audit requires rules for both tools. Missing configuration is never a passed audit.

`factory change review` automatically loads the default policy when it exists. `--audit-policy path/to/policy.json` selects another workspace-contained file. Existing stale-proof, coverage and unmatched-path findings keep their priority. Added findings, hashes, gaps and branch witnesses travel in the review JSON, with summaries in Markdown and finding nodes in Mermaid. IDE and agent integrations calling the shared change-review API receive the same lane without separate analysis logic.

## Receipt boundaries

- SHA-256 binds the policy and inspected source. Changing either changes the audit digest. Source changes during analysis reject the result.
- Code is parsed, never imported or executed; no models, network calls or credentials are needed. The implementation uses CF's cross-platform Python runtime; this change was tested locally on Windows.
- Scope: declared Python functions and qualified class methods, up to 128 rules, 64 files, 1 MB per file and 10,000 AST nodes per file. No whole-repository coverage claim.
- Guard-path analysis supports sequential statements, branches, early returns/raises and direct awaited guard statements. Exploration is bounded to 64 live paths, 32 nesting levels and 4,096 statement-path steps.
- Loops, exception handlers, context managers, decorators, identity rebinding, short-circuit expressions and other unsupported semantics remain `incomplete`. An absent expected effect is incomplete, not a pass.
- A guard counts only as an unconditional standalone call statement on a path. Its declared semantics must be “raise on denial.” This assumption needs review; a function name does not prove authorization.
- Aliases, helper-function behavior, dynamic dispatch, concurrency and runtime branch feasibility are not proven. Use runtime tests, independent validators and human review for those boundaries.
- Receipts are content-addressed, not signed approvals. `no_structural_findings` means only that these checks found no issue in the declared, supported scope.

For solo developers: catch an omitted check and see where it belongs. For teams: make the convention and unsafe branch inspectable. For enterprise reviewers: retain exact policy/source bindings and explicit coverage gaps rather than another unexplained green badge.

## Published repository quality grading method

CI pins `code-factory-2-forge==0.10.8` and runs
`forge qa --repo-wide --root . --strict`. Its report lists the actual source
inventory in `metrics.scope.code_files`; generated, ignored and excluded paths
are outside that inventory. Compare receipts only when scope and parser versions
match.

The composite score is `35*T + 25*C + 25*S/100 + 15*D`:

- `T` is the fraction of inspected public functions whose names occur as whole
  words in discovered test source, rounded to two decimal places.
- `D` is the documented public-function fraction, also rounded to two decimals.
- `C` is 1 when maximum complexity is at most 10; otherwise it is
  `max(0, 1 - (maximum_complexity - 10)/10)`.
- `S` starts at 100, subtracts the pinned scanner's security-rule penalties and
  is floored at zero. This is a rule score, not vulnerability prevalence.

For Python, complexity starts at 1 and counts branches, loops, exception
handlers, context managers, assertions, conditional expressions and boolean
operators in the function AST. Other languages use their configured parsers.
This is not call-graph complexity. Ruff's C901 metric and architecture file/line
budgets are separate checks and can disagree with this metric.

Forge assigns A at 85, B at 70, C at 55 and D at 40. Complexity above 10 prevents
an A/B result; syntax or unsupported-parser findings fail the grade. CF's CI
adds stricter requirements: A, composite at least 97.9, static attribution at
least 99.85%, maximum complexity 10,
no findings or unreadable source, and at most 460 tracked Python files.

The separate, unrounded `attribution.rate` counts function units passing both
the test-name linkage and complexity checks, with parser/syntax failures adding
failed units. Anonymous functions cannot satisfy the name linkage. Name linkage
is static test intent: even a passing test mentioning a function does not prove
that every branch ran or that its assertions detect a defect. Behavior tests,
mutation evidence and runtime coverage must be reported separately.

Neither this grade nor attribution measures detection precision or recall.
Those require independently labeled defects and clean controls, with false
positives, false negatives, corpus provenance and evaluation scope published.

### Argument and exception oracles

The Python test-intent scanner recognizes standard mock argument and await
assertions, including `assert_called_once_with`, and imported `pytest.fail`
checks used to reject an unexpected successful operation. A direct invocation
of that same mock before its assertion remains a self-check; unrelated calls
do not establish an independent oracle. Swallowed `pytest.fail` exceptions,
unreachable checks and suppressing `finally` returns remain findings.

A direct `pickle.loads(pickle.dumps(value))` or matching dill round-trip in a
test source remains visible as an informational security finding with
`input_provenance=direct_local_serialization`. It does not alone block the scan.
This classification concerns byte provenance, not safety of custom reducers.
External bytes, transformed buffers, mismatched libraries, source-visible
serializer replacement and production-source round-trips retain high severity.
These are static recognitions; runtime negative controls and independent
accuracy measurements remain separate evidence.

### External-source regression corpus

`tests/fixtures/external_oracle_cases.json` contains 31 cases extracted from
requests, rich and Click, with upstream commit, original path, source digest,
label rationale and original license text. The test runs those sources through
the real scanner. It preserves three genuine missing-oracle controls and checks
28 legitimate argument/exception or invoked local helper oracles. The cases were selected after reading
scanner findings, so they are public regressions, not an independently held-out
corpus and not a population precision/recall estimate.

The original eight seeded benchmark cases remain a separate control suite.
Neither adding regressions nor a reduction in findings establishes accuracy.
Full-repository comparisons use identical upstream snapshots and record remaining
findings rather than treating a smaller count as a verified clean result.


### Completion-only tests: runtime oracle reconciliation

A valid-input validator or no-exception smoke test may have an observable
runtime oracle even when its source contains no assertion. CF continues to flag
such tests by default. Names, comments and bare calls do not clear a finding.

For a trusted runner's per-test evidence, use:

```powershell
factory audit security --root . --json `
  --oracle-evidence .factory/test-oracles/observations.dsse.json `
  --oracle-trust-root .factory/test-oracles/trust-root.json `
  --oracle-trust-sha256 <operator-pinned-public-trust-root-sha256> `
  --oracle-environment-sha256 <expected-runner-contract-sha256>
```

The DSSE payload type is
`application/vnd.factory.test-oracle-attestation.v1+json`; its schema is
`factory.test-oracle-attestation.v1`. The payload requires `issued_at`,
`expires_at` (at most 24 hours apart), `source_manifest_sha256` from the initial
scan, `environment_sha256`, `authority: "none"`, and 1–460 `tests`.
The environment contract should bind the exact interpreter, dependency lock,
runner image, argv, configuration and execution policy. Pin it independently of
the received attestation. The public trust-root key must have the
`oracle-verifier` role; absent, ambiguous or revoked keys are rejected. Keep the
signing key in the trusted runner, never in the candidate repository.

Each test records `path`, `line`, `symbol`, `test_sha256`, `baseline` and
`mutation`. Baseline requires `status: "PASS"`, `phase: "call"`,
`collection_complete: true`, all collected `case_ids` and `report_sha256`.
Mutation requires the exact same cases, `status: "FAIL"`, `phase: "call"`,
`failure_kind: "assertion"` or `"exception"`, `report_sha256`, and
`source_path`, `source_sha256`, `mutant_sha256` for changed production code.
Both report digests refer to the retained execution artifacts. The runner must
actually run the baseline and source mutation, distinguish call failures from
collection/setup/teardown errors, and attest every parameterized case; a
suite-wide mutation score is insufficient. Existing `factory senior replay`
and repair comparison primitives can support isolated temporary source copies.

CF verifies the signature, current test/production source hashes, source and
scanner-configuration manifest, expected environment, exact qualified test
identity, complete matching case sets and freshness. It rejects partial,
misbound, tampered or stale evidence. Timeouts, crashes and fixture failures do
not qualify. It clears only completion-only hollow findings: ineffective,
constant or swallowed assertions, nested checks and empty tests remain findings.
Security findings are unaffected. The `runtime_oracles.reconciled` report keeps
the original static finding, per-test evidence, signer and receipt hashes.

This command verifies an operator-trusted runner's attestation offline; it
neither executes the submitted project nor independently proves that the signer
ran the mutation. Its scope is the recorded mutation and test. It is not a
population accuracy measurement, proof of all behavior, or release approval.
Runtime evidence is opt-in on `audit security`; the aggregate `scan` command
retains its existing static behavior. Store generated observations and reports
outside tracked source, for example as private CI artifacts.
