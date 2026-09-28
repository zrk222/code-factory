# Code Factory

Code Factory is a Python package and command-line tool for collecting local
software review evidence. It can inspect a repository, run configured checks,
and produce receipts for a human to review. It does not certify software,
guarantee that defects are absent, or approve a release.

## 0.47.0 source preview

**Fixed:** editor audit views now expose missing and incomplete checks.
**Changed:** Junie's route connects a diff to bounded evidence and a concrete
repair handoff. **Added:** VS Code/Open VSX 1.0.2 evidence tree, JetBrains
1.0.2 CF + ForgeLine tab, and a native [OpenCode plugin](plugins/code-factory-opencode/README.md).
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

The [repository self-audit receipt](evidence/self-audit/code-factory-2026-09-24.json)
records the checks run against Code Factory, including blocked and unavailable
checks. It is local evidence for review, not an independent audit or release
approval.
<!-- mcp-name: io.github.zrk222/code-factory -->

## Release controls

Candidate preflight requires release-cadence admission and strict architecture
health. Protected main requires CI and a separate specialty AI source review;
the coordinator records that assessment, separately from test evidence. It is
not a second human approval. Provider publication and marketplace approval are
separate outcomes. See [release channels](docs/RELEASE_CHANNELS.md).

Architecture health checks growth budgets. ForgeLine's repository inventory
and feature QA are separate checks. The [current gap review](docs/AUTONOMOUS_OPS_EDITOR_PLAN.md)
records this candidate's failed repo-wide assessment and its parser and
complexity limits. A prior score does not establish this candidate's quality;
static signals are neither executed coverage nor a security certification.

## More detail

- [Engineering review workflow](docs/PROOF_REVIEW_WORKFLOW.md)
- [GitHub Proof Review](docs/GITHUB_PROOF_REVIEW.md)
- [Commercial availability and limits](docs/COMMERCIAL_PACKAGING.md)
- [Audit condition inventory](docs/AUDIT_CONDITION_INVENTORY.md)
- [Runtime assurance limits](docs/RUNTIME_ASSURANCE.md)
- [Release channels and publication evidence](docs/RELEASE_CHANNELS.md)
- [Changelog](CHANGELOG.md)
- [Documentation index](docs/DOCUMENTATION_INDEX.json)
