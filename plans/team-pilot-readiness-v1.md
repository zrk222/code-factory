# Plan: Team Pilot readiness v1

Spec: `specs/team-pilot-readiness-v1.md`

Architect verdict: PASS

## Atomic tasks

- [x] T1 | slice=factoryline | files=factoryline/team_pilot.py | verify=`python -m pytest -q tests/test_team_pilot.py` | Add exact manifest, commercial-boundary, evidence-path, digest, receipt, and artifact validators without process or network access.
- [x] T2 | slice=factoryline | files=factoryline/cli.py | verify=`factory team-pilot readiness --help` | Add JSON-safe readiness and receipt-verification commands with explicit non-zero errors.
- [x] T3 | slice=tests | files=tests/test_team_pilot.py | verify=`python -m pytest -q tests/test_team_pilot.py` | Prove ready receipt, authority preservation, cap/governance/delivery rejection, path/digest drift, commercial drift, and receipt tampering.
- [x] T4 | slice=docs | files=docs/TEAM_PILOT_LAUNCH.md,docs/COMMERCIAL_PACKAGING.md,docs/ENTERPRISE_TEAMS_OPERATIONS.md,docs/OVERVIEW.md | verify=`rg -n "team-pilot readiness" docs/TEAM_PILOT_LAUNCH.md` | Publish a concise operator workflow and retain customer-managed, not-purchasable boundaries.
- [x] T5 | slice=README.md | files=README.md | verify=`rg -n "team-pilot readiness" README.md` | Link the bounded Team Pilot use case without turning the README into a sales promise.
- [x] T6 | slice=docs | files=docs/AKU_TEAM_PILOT_LAUNCH.md | verify=`python -m pytest -q tests/test_team_pilot.py` | Record reusable intent, procedure, tools, metadata, governance, continuations, and validators.
- [x] T7 | slice=smoke | files=smoke/team-pilot-readiness-v1.json | verify=`forge smoke team-pilot-readiness-v1 --root .` | Bind a happy-path receipt to reverse-classical smoke evidence.

## Release boundary

This plan delivers a local, deterministic readiness gate and documentation. It
does not select a partner, issue an offer, sign a contract, collect payment,
provision any account, deploy a service, change a Marketplace price, or publish
an external commercial claim.
