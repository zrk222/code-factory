# Code Factory

Code Factory is a Python package and command-line tool for collecting local
software review evidence. It can inspect a repository, run configured checks,
and produce receipts for a human to review. It does not certify software,
guarantee that defects are absent, or approve a release.

## Install and start

```powershell
python -m pip install factoryline-code-factory
factory --help
factory guide
```

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

Architecture health checks growth budgets. The 2026-09-26 ForgeLine reassessment
grades this checkout C (62.3/100; 162 findings), with the hard complexity gate
still failing. This scanner uses AST branch count; the earlier deep-audit
complexity-83 score uses a different metric, so the figures are not directly
comparable. Its test-intent and security scores are static signals, not executed
coverage or a security certification. Historical receipts remain snapshots.
The repository-wide quality gate is blocked; no grade-A claim is made.

## More detail

- [Engineering review workflow](docs/PROOF_REVIEW_WORKFLOW.md)
- [GitHub Proof Review](docs/GITHUB_PROOF_REVIEW.md)
- [Commercial availability and limits](docs/COMMERCIAL_PACKAGING.md)
- [Audit condition inventory](docs/AUDIT_CONDITION_INVENTORY.md)
- [Runtime assurance limits](docs/RUNTIME_ASSURANCE.md)
- [Release channels and publication evidence](docs/RELEASE_CHANNELS.md)
- [Changelog](CHANGELOG.md)
- [Documentation index](docs/DOCUMENTATION_INDEX.json)
