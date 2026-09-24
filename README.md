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

## Release controls

Candidate preflight requires release-cadence admission and strict architecture
health. The current architecture findings must be resolved before a candidate
passes. Public publishing workflows also depend on GitHub environments with a
required reviewer who is not the workflow initiator and with self-review
disabled. See [release channels](docs/RELEASE_CHANNELS.md) and
[contributor guidance](CONTRIBUTING.md).
The self-audit receipt reports the live repository settings; publication stays
blocked while independent-review protection is incomplete.

## More detail

- [Engineering review workflow](docs/PROOF_REVIEW_WORKFLOW.md)
- [Runtime assurance limits](docs/RUNTIME_ASSURANCE.md)
- [Release channels and publication evidence](docs/RELEASE_CHANNELS.md)
- [Documentation index](docs/DOCUMENTATION_INDEX.json)
