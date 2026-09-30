# Deep audit evaluator verification

## CI research and upgrade: 2026-09-28

The earlier measurements below describe a historical evaluator slice. They do
not establish current whole-repository security or behavioral coverage.

### Changes prepared for this candidate

| Change | Benefit and evidence boundary |
| --- | --- |
| Two pytest workers on all nine existing OS/Python jobs | Keeps platform coverage and required check names. JUnit artifacts and 20 slowest checks expose failures and timing. A local run passed 1,899 checks with 8 skips in 241.32 seconds; no matched serial baseline was measured. |
| Cancel superseded IntelliJ runs by PR/ref | New commits share a concurrency group, preventing obsolete eight-IDE verification runs from continuing independently. Existing applicability checks and required statuses stay active. |
| CodeQL 4.38.2, pinned to its resolved commit | Automatic PR/main analysis and weekly full scans for Python, JS/TS, GitHub Actions, and compiled Java/Kotlin. Security-extended queries, native SARIF, source locations and dataflow traces support concrete repairs. Scan completion is not alert clearance. |
| Scoped mutmut 3.8.0 workflow | Explicit production files and reviewed behavioral checks; two mutation workers, 20-minute execution bound and 30-minute job bound. Tracked source copies preserve root fixtures while excluding untracked files. Receipts bind snapshot bytes. All survivors, absent checks and incomplete counters fail; logs, finding IDs and up to 50 survivor diffs are retained. |
| Reassessment integrity | Pinned ForgeLine 0.10.8 is rerun against current source and policies; a saved A report must match its results and content digest (Git text line endings normalized to LF). A filename/date or self-asserted metrics cannot retire an earlier failing receipt. |

Mutation audit workflow: `.github/workflows/mutation-audit.yml`. Run with explicit
JSON source/check lists in GitHub Actions, or on Linux with `MUTATION_SOURCES`,
`MUTATION_TESTS` and `MUTATION_OUTPUT` set, then `python scripts/ci_mutation_gate.py`.
Without `MUTATION_SOURCES`, `MUTATION_BASE` selects changed Python production
files using an endpoint diff that works in shallow checkouts. Empty scope is
reported as blocked/unproven, never a passing audit. This workflow is available
for deliberate runs; it is not an automatic whole-code mutation merge gate.

### Research findings and useful next layers

1. **Trace input through callers, storage and sinks.** CodeQL global dataflow
   crosses function boundaries and can expose command injection, unsafe parsing
   and workflow artifact/cache poisoning. Dynamic dispatch, framework models,
   generated code and unbuilt dependencies remain coverage limitations. Plain
   Semgrep CE is per-file; do not label it whole-program interfile analysis.
   Sources: [CodeQL Python dataflow](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/),
   [Actions queries](https://codeql.github.com/codeql-query-help/actions/),
   [Semgrep engine scope](https://semgrep.dev/docs/writing-rules/glossary).
2. **Challenge behavioral assertions independently.** Mutmut determines relevant
   checks and supports incremental work, but a survivor can mean an assertion
   gap or an equivalent mutation. Retain the exact counterexample for review;
   never suppress it solely to raise a score. Module/import-time logic and
   non-Python code require other engines. Mutmut 3 needs POSIX/fork, so native
   Windows execution is unsupported. Source:
   [Mutmut documentation](https://mutmut.readthedocs.io/en/latest/).
3. **Generate API state transitions from contracts.** Schemathesis can exercise
   create/read/update/delete sequences, rejected invalid input, ignored auth,
   schema conformance and resource lifecycle failures. Use an ephemeral service,
   seeded tenants, an explicit endpoint allowlist, request/time budgets and
   no production credentials. OpenAPI links and independently reviewed domain
   invariants are the behavioral oracle; missing contracts cannot be inferred
   as correct. Preserve seeds and minimized reproductions. This adapter remains
   planned, not executed in this candidate. Sources:
   [Stateful testing](https://schemathesis.readthedocs.io/en/stable/explanations/stateful/),
   [Available checks](https://schemathesis.readthedocs.io/en/stable/reference/checks/).
4. **Keep fast feedback and full depth separate.** Run changed-scope adequacy for
   iteration, full scans on main/schedule, and platform parity before release.
   Cache dependencies using dependency hashes; cached verdicts are not fresh
   audit evidence. Measure median/p95 elapsed time, worker time, executed scope,
   uncovered symbols, surviving mutants, alert recurrence and reproduction
   success before claiming speed or quality improvements. Sources:
   [pytest distribution](https://pytest-xdist.readthedocs.io/en/latest/distribution.html),
   [GitHub dependency caching](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching).

### Release and integration criteria

Native CodeQL results must be reviewed and rebound to a deep-audit candidate
manifest before they count as CF deployment evidence. Missing SARIF, missing
analyzer execution, uncovered paths and absent sandbox runtime stay explicit
gaps. Existing Docker-based deep-audit lanes require an available sandbox and
pinned adapters; a configured workflow does not prove their execution.

CF can own CI evidence, generated contract/property/fuzz checks and independent
mutation challenges. Authorship cannot be reliably inferred from source, and
no scanner replaces all behavioral expectations. Do not delete regression
checks because they were generated by an LLM. Retire a check only after its
requirement has equivalent measured coverage and reviewed counterexamples.

Each actionable finding should retain candidate/source digest, tool version,
rule or mutant ID, path/line, flow or reproduction, impact, suggested repair,
owner and verification command. AI repair proposals receive specialty-agent
review and a fresh rerun; they cannot grant their own release approval.

Current execution boundary: local regression and adapter contract tests passed;
the new Linux mutation engine and remote CodeQL jobs still require native CI
execution. The available local Windows runtime cannot execute mutmut directly.

---

Scope: Deep Defect Mesh plan T4 only. Windows, Python 3.11.

## Passing checks

- `python -m pytest -q`: **1190 passed, 3 skipped**, 183.11 seconds.
- `python -m pytest -q tests/test_deep_audit.py tests/test_deep_audit_contract.py tests/test_deep_audit_sarif.py`: **65 passed**.
- `specline strict deep-defect-mesh-v1 --root .`: zero warnings.
- `specline verify-validators deep-defect-mesh-v1 --root .`: all 13 requirement mutations killed.
- `specline audit deep-defect-mesh-v1 --root . --files factoryline/deep_audit.py --slice factoryline`: no drift.
- `forge qa deep-audit-decisions --ssat specs/deep-audit-decisions.ssat.yaml --strict --root .`: passed for the three declared entry points; maximum reported complexity 4. This static score is not a production certification.
- Scoped Forge smoke passed and stub rejection passed. Stub rejection is structural evidence, not a substitute for semantic mutation testing.
- A separate in-memory mutation replaced `_canary_actions` with an empty result. The canary test selection produced **7 failures, 1 pass**, demonstrating detection of that specific bypass. Production files were not modified by the mutation.

## Review history and boundaries

Initial QA rejected evaluator/status complexity. Both were decomposed before
the final passing QA and regression runs. The Forge CLI permits arch-gate
recovery after a failed review; a later review invocation also rejected the
already-smoked state transition. Therefore the state label alone is **not**
used as proof of review. The separate final strict QA and native test results
above are the completion evidence for this slice.

Spec/plan gates were recorded as `agent_prepared_for_user_review`, not independent
human approval. The architecture gate was invoked by the assistant under the
user's implementation request. No external analyst, device, scanner execution,
marketplace or production approval is claimed. No release was published.

Remaining plan work includes CLI/MCP/Mission Control, graph lineage, repair-loop
comparison and broader public documentation. Receipt self-hashes detect accidental
or unrehashed changes, not a malicious local writer able to recompute a hash.
