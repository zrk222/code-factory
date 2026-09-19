# Code Factory 0.46.6 — Control-plane drift you can inspect

## The problem this release closes

An agent can preserve the shape of a workflow while quietly changing the
control plane around it: a capability disappears, a schema moves, an assurance
lane is disabled, or an authority bit is widened. A green build does not make
that change safe. Code Factory 0.46.6 compares the approved projection with the
current one before the next handoff and makes the difference reviewable.

## What changed

- Added `factory agent drift` to compare a baseline projection with the current
  control-plane projection. It emits `CLEAR`, `REVIEW_REQUIRED`, or `BLOCKED`
  and can write a local JSON receipt.
- Added `factory agent drift --verify` to re-check the receipt digest, verdict,
  marker, and all-false authority boundary without contacting an agent or
  provider.
- Added fail-closed classifications for authority escalation, schema changes,
  removed features, disabled assurance, weakened blocking policy, and removed
  assurance lanes. Non-sensitive additions remain visible as review work.
- Renewed the architecture-health acceptance with exact measured values,
  named human ownership, and an expiry. The known CLI/core-surface debt stays
  visible rather than being mistaken for a healthy architecture.
- Added the OpenCodeReview pattern assessment to the release decision: CF
  already has resumable hash-bound sessions, rule search, line-aware audits,
  and signed supply-chain receipts; this release adds the missing deterministic
  control-plane drift gate instead of duplicating those mechanisms.

## Operator path

```powershell
python -c "from pathlib import Path; import json; from factoryline.agentic_control import agentic_control_projection; Path('baseline.json').write_text(json.dumps(agentic_control_projection(Path('.')), indent=2), encoding='utf-8')"
python -m factoryline.cli agent drift baseline.json --root . --out drift.json --json
python -m factoryline.cli agent drift --verify drift.json --json
```

The receipt is local, deterministic, and hash-bound. It does not run a model,
execute source, mutate a branch, approve a merge, publish an artifact, or
prove runtime behavior.

## Verification

```powershell
python -m pytest -q
python -m ruff check factoryline/agentic_control.py factoryline/cli.py tests/test_agentic_control.py
python -m factoryline.cli audit security --root . --json
python -m factoryline.cli audit evals --root . --json
python -m factoryline.cli architecture health --root . --json
python -m build
python -m twine check dist\factoryline_code_factory-0.46.6-py3-none-any.whl dist\factoryline_code_factory-0.46.6.tar.gz
```
