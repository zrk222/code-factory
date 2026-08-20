# Proof-Delta Loop

The Proof-Delta Loop stops a supervised mission retry from becoming another
unbounded attempt at the same failure. Before the Mission Graph accepts a
transition from `correction_required` back to `creator_running`, the retry must
be bound to:

- the latest failed completion criterion;
- a different candidate diff; and
- at least one new hash-checked evidence reference.

The receipt is deterministic. It does not run the candidate, apply a repair, or
decide that the candidate is correct. The ordinary fresh-worker-context and
independent-validator boundaries remain in force.

## Candidate packet shape

Each supplied candidate receipt is local JSON with this bounded shape:

```json
{
  "schema": "factory.mission.candidate.v1",
  "mission_id": "mission-id",
  "candidate": {
    "diff_sha256": "<sha256>",
    "changed_paths": ["src/example.py"]
  },
  "evidence": [
    {"path": "receipts/failure-case.json", "sha256": "<sha256>", "kind": "counterexample"}
  ]
}
```

Candidate paths are sorted workspace-relative paths. Evidence must be a current
file below the workspace and use one of the explicit kinds: `counterexample`,
`test_result`, `trace`, `proof_receipt`, or `external_artifact`.

## Create and verify

```powershell
factory mission proof-delta create .factory/missions/<mission>/mission.json `
  --root . `
  --prior-candidate receipts/candidate-before.json `
  --repair-candidate receipts/candidate-after.json `
  --failure .factory/missions/<mission>/validation-failure.json `
  --criterion C-01 `
  --out .factory/proof-deltas/<mission>-C-01.json `
  --json

factory mission proof-delta verify .factory/proof-deltas/<mission>-C-01.json --root . --json
```

The output is either `PROOF_DELTA_ADVANCE` or `PROOF_DELTA_NO_EVIDENCE_GAIN`.
The latter is a deliberate halt signal: keep the mission paused and improve the
evidence packet instead of spending another retry.

## Mission Graph rule

A `validation_failed` transition moves the mission to `correction_required`.
The next `retry` event requires a verified `factory.mission.proof-delta.v1`
receipt that matches the current candidate receipt, latest validation failure,
and failed criterion. Legacy retry receipts and stale evidence are rejected.

Graph Ops projects the resulting retry evidence into a read-only **proof_delta**
lane. An admitted packet is still only a review point: it does not admit a
worker, apply a repair, merge, publish, deploy, sign, or message anyone.
