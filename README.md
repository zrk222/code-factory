# Code Factory

Code Factory + ForgeLine (CF/FL) is a robust, local-first code-audit factory.
It starts by collecting local software review evidence for the candidate change.
It connects requirements, architecture checks, Python AST security analysis,
behavioral test evidence, workflow integrity, specialty AI review, and
actionable repair. Its receipts support review; the tool does not certify
software, guarantee that defects are absent, or approve a release.

## 0.47.0 audit workflow preview

**Fixed:** editor audit views now expose missing and incomplete checks.
**Changed:** Junie's route connects a diff to bounded evidence and a concrete
repair handoff. **Added:** project-neutral `factory audit workflows` contracts
with hash-bound candidate and execution evidence, plus VS Code/Open VSX 1.1.0
evidence tree, JetBrains 1.1.0 CF + ForgeLine tab, and a native
[OpenCode plugin](plugins/code-factory-opencode/README.md).
**Candidate detection fixes:** the Python scanner flags tests without a local
assertion, constant-true assertions, and reflexive comparisons. Declared tenant
reads can be checked with `factory audit security --tenant-read-call db.get`.
That legacy form requires `tenant_id=tenant_id`. For positional or renamed
arguments, declare the mapping, for example
`--tenant-read-binding db.get=position:1:tenant_scope`; keyword mappings use
`db.get=keyword:tenant_id:tenant_scope`. Positional indexes start at zero. The
scanner requires the named, required function parameter to reach the declared
argument without reassignment; configure exactly one binding per read call. This
does not prove that the value is the authenticated tenant or that runtime access
is isolated.
The unchanged eight-case public regression corpus now gives 6 true positives,
2 true negatives, and no false positives or false negatives locally, with the
same tenant-read contract applied to defective, repaired, and clean inputs.
This is a small development regression result, not independent accuracy,
runtime coverage, or release approval. CI verification is still required.
The [autonomous ops plan](docs/AUTONOMOUS_OPS_EDITOR_PLAN.md) explains the
proposed Observer Agent loop and its gates. These versions remain release
candidates until each channel has a verified provider publication receipt.

## Graph Ops in action

![Full-page Graph Ops dashboard capture: lineage runs, a forensic finding, first semantic divergence, recovery preview, guarded actions, graph lanes, and the next action](docs/assets/marketplace/graph-ops-forensics.png)

This full-page local capture shows Graph Ops tracing a change from sealed
lineage through a forensic finding to a proposed recovery path. The guarded
action remains locked; the dashboard is a read-only inspection surface.

![Graph Ops Counterfactual Arena comparing a rejected patch, an eligible refactor, and a verified repair candidate](docs/assets/marketplace/graph-ops-proofsearch.png)

The Counterfactual Arena compares repair candidates and shows their evidence
and risk. [Winner controls](docs/assets/marketplace/graph-ops-proofsearch-controls.png)
and the [Evidence Frontier](docs/assets/marketplace/graph-ops-evidence-frontier.png)
show how a reviewer can inspect the rationale and choose the next proof.

The current Graph Ops UI also separates native deep-scan progress, evaluated
deep-audit receipts, six runtime lanes, and individual JUnit test cases. Each
panel labels its evidence state and next repair. Filter or search the recorded
tests, then load more cases as needed; an inventory or a missing report never
appears as a passing run. The JUnit reader accepts up to 10,000 cases and marks
larger or malformed reports incomplete. A JUnit report is local observation
without a current-candidate binding.

![Updated Graph Ops audit results: labeled native deep scan, evaluated audit, six runtime lanes, and searchable individual test results](docs/assets/marketplace/graph-ops-audit-results-0.46.9.png)

This local UI capture shows each reported test case with its status. The audit
cards keep checks without a bound result explicitly marked not run.

<details>
<summary>Supplement: annotated live Assembly telemetry</summary>

![Annotated Graph Ops telemetry capture: callouts identify the human waiting state, live run counts, evidence actions, and read-only boundary](docs/assets/marketplace/graph-ops-live-annotated.png)

The labels explain an [original local Assembly capture](docs/assets/marketplace/factoryline-0.44-live-dashboard.png).
That pictured run is waiting for human input; it does not imply release approval
or that every check passed.

</details>

## Install and start

```powershell
python -m pip install factoryline-code-factory
factory --help
factory guide
```

In an interactive terminal, `factory` checks PyPI and caches the result for up
to 24 hours, then prints a notice when a newer version is available. Two
simultaneous first runs can both check. It never downloads or installs the
update. The check is quiet in CI, JSON output, server/MCP, help, version, and
non-interactive runs; set `FACTORY_DISABLE_UPDATE_CHECK=1` to turn it off. The
plain PyPI request does not include a project path, account identifier, or
usage data.

Run repository commands from the project being reviewed. `factory guide` is a
read-only orientation; it does not run tests or agents.

## Inspect this repository

These commands show the current architecture policy, the bounded static
security scan, and the runtime-audit setup:

```powershell
factory architecture health --root . --json
factory audit security --root . --json
factory runtime-audit status --root . --json
```

`factory audit security` checks a limited set of source patterns. It is not a
penetration test. The runtime audit needs a separately reviewed plan and its
own environment evidence. A status of `NOT_RUN` or a clean static scan is not a
complete project audit.

To display individual tests in Graph Ops, run your suite with a JUnit report at
`.factory/test-reports/pytest.xml` (for example,
`python -m pytest --junitxml=.factory/test-reports/pytest.xml`). The local
Studio reads the report and labels its candidate binding `UNBOUND`; it does
not infer that those results still apply after source changes.

The prior snapshot's [repository self-audit receipt](evidence/self-audit/quality-reassessment-2026-10-04.json)
records **A (97.9/100)** and 1,055/1,085 functions attributed to test intent
(97.24%). That static measurement applies to its recorded source digest;
it is not a grade for later edits, runtime coverage, or certification.

ForgeLine 0.10.8 computes Python complexity for public module functions and
public class methods in its recorded `metrics.scope.code_files`; names starting
with `_` are excluded. Its AST metric counts branches, boolean alternatives,
exception handlers, `with`, and assertions. Ruff C901 uses a different McCabe
metric and also checks private functions. CI therefore runs
`python -m ruff check --select C901 factoryline tests` separately at limit 10.
The ForgeLine maximum must not be read as the maximum of every Python function.
CI also checks action and reusable workflow references for immutable commit
pins; the generic workflow evidence validator alone does not inspect those refs.
<!-- mcp-name: io.github.zrk222/code-factory -->

## Release controls

Candidate preflight requires release-cadence admission and strict architecture
health. Protected main requires CI and a separate specialty AI source review;
the coordinator records that assessment, separately from test evidence. It is
not a second human approval. Provider publication and marketplace approval are
separate outcomes. See [release channels](docs/RELEASE_CHANNELS.md).

Architecture health checks growth budgets. ForgeLine's repository inventory
and feature QA are separate checks. The [current gap review](docs/AUTONOMOUS_OPS_EDITOR_PLAN.md)
records how the published ForgeLine 0.10.7 graded this source F/70.7 while
parser-corrected ForgeLine 0.10.8 grades it A/95.1. CF 0.47.0 requires 0.10.8
and checks real MJS, TS, and TSX feature QA during `factory doctor --strict`.
Static signals are neither executed coverage nor a security certification.

## More detail

- [Engineering review workflow](docs/PROOF_REVIEW_WORKFLOW.md)
- [GitHub Proof Review](docs/GITHUB_PROOF_REVIEW.md)
- [Commercial availability and limits](docs/COMMERCIAL_PACKAGING.md)
- [Audit condition inventory](docs/AUDIT_CONDITION_INVENTORY.md)
- [Runtime assurance limits](docs/RUNTIME_ASSURANCE.md)
- [Release channels and publication evidence](docs/RELEASE_CHANNELS.md)
- [Changelog](CHANGELOG.md)
- [Documentation index](docs/DOCUMENTATION_INDEX.json)
