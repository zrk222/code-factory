# Code Factory 0.46.5 — First Lap, one bounded starting line

## The moment this release addresses

An agent can be fast and still begin from an ambiguous mission, a stale
verifier, or a contaminated holdout. Code Factory 0.46.5 gives every operator
one small, inspectable starting line before autonomy is considered: a mission,
observable journeys, verifier-only negative cases, and a status projection that
never pretends those files are proof of correctness.

## What changed

- Added `factory first-lap init` to create `MISSION.md`, `END-TO-END.md`, and
  `.factory/holdouts/HOLDOUT.md` with an immutable, hash-bound initialization
  receipt.
- Added `factory first-lap status` for a read-only integrity check and one
  fact-derived next action. It distinguishes `NOT_INITIALIZED`, `INITIALIZED`,
  and `BLOCKED` without running code or opening holdouts.
- Added three-point verifier calibration: the approved candidate must pass, a
  deliberate defect must fail, and the wrong candidate must be inconclusive or
  blocked. A failed calibration emits `E_CALIBRATION_FAILED`.
- Added verifier-only holdout boundary checks with stale, unavailable, scope,
  and builder-access contamination outcomes.
- Added human-observed First Lap sequencing (`intake` → `candidate_binding` →
  `validation` → `failure_handling` → `cleanup` → `handoff`).
- Added typed failure classification. Only `transient_provider_failure` is
  retryable; product, identity, stale-evidence, and setup failures remain
  review events.
- Added incident promotion from
  `incident → failure code → invariant → reproducer → mutation → permanent
  gate → owner`, retaining human approval as a required gate property.
- Added the read-only `factory.first_lap_status` tool to the stdio MCP
  inventory and the progressive WebMCP manifest. CLI, MCP, and WebMCP return
  the same bounded status contract.
- Added `factory.agui_review_events` and `factory agui review-events` as a
  controlled/declarative presentation bridge. Mission Control and IDEs can
  render stable `RUN_STARTED → STATE_SNAPSHOT → REVIEW_CARD → RUN_FINISHED`
  events, while MCP2 `input_required` decisions remain human-owned interrupts.
  Event IDs and payloads are hash-bound, bounded, and reject credentials, raw
  prompts, and transcripts.
- Aligned the release surfaces to core `0.46.5`, VS Code/Open VSX `0.9.8`, and
  JetBrains `0.9.6`.

## The operator path

```powershell
factory first-lap init --root . --mission "Ship the approved outcome" --journey "Happy path completes" --holdout "Revoked access is rejected"
factory first-lap status --root . --json
factory first-lap calibrate cases.json --root . --json
factory first-lap holdout boundary.json --root . --json
factory first-lap observe events.json --json
factory first-lap verify --calibration calibration.json --holdout holdout.json --observed observed.json --root . --json
```

For an IDE or coding agent, connect the local server with
`factory mcp serve --root .`, call `factory.first_lap_status`, and use the
reported next action. A compatible browser can discover the same projection
through WebMCP. These are read-only facts; they do not start an agent, run a
test, alter a gate, approve a merge, publish a package, deploy, sign, or access
credentials.

## Why this is useful

The release makes the first handoff legible: people can see the intended
outcome, the observable path, the forbidden cases, and whether the generated
contract is intact before a worker is trusted with a repair. A changed file is
not automatically a calibrated verifier, and a green result is not a release
approval. The gain is a shorter route to honest review, not a claim of perfect
software or guaranteed provider approval.

## Truth ledger

**Locally verified:** First Lap schemas, CLI dispatch, stdio MCP and AGUI tools,
WebMCP manifest entries, artifact-integrity checks, calibration/holdout/
observation gates, typed retry classification, incident-promotion receipts,
and AGUI sequence/hash/sensitivity checks.

**Requires the project’s own evidence:** code correctness, test quality,
workflow coverage, performance, provider health, store approval, and production
readiness.

**Not performed by this release:** provider uploads, credential access, merges,
deployments, signing, device execution, or automatic human decisions.

## Verification

The release gate is the repository’s normal test and package path:

```powershell
python -m pytest -q
python -m compileall -q factoryline
python -m build
python -m twine check dist\factoryline_code_factory-0.46.5-py3-none-any.whl dist\factoryline_code_factory-0.46.5.tar.gz
```
