# First Lap: make autonomy earn its way in

The first lap is the shortest trustworthy path through Code Factory. It turns
the original request into three plain-language artifacts, calibrates the
verifier against a real defect, proves that holdouts stayed independent, and
requires one human-observed lifecycle before an agent can be treated as
supervised-ready.

## 1. Generate the three files

```powershell
factory first-lap init --root . `
  --mission "Ship the approved outcome without violating its forbidden outcomes." `
  --journey "A user can complete the approved happy path" `
  --journey "A failed request is rejected without partial state" `
  --holdout "A revoked identity cannot read another tenant"
```

This writes `MISSION.md`, `END-TO-END.md`, and verifier-only
`.factory/holdouts/HOLDOUT.md`. The files and incident-ledger reference are
hash-bound in `.factory/first-lap/init.json`; existing user-authored files are
preserved.

## 2. Calibrate every release-critical verifier

```powershell
factory first-lap calibrate verifier-cases.json --root . --json
```

The input must include `approved_candidate: pass`, `defective_candidate: fail`,
and `wrong_candidate: inconclusive` or `blocked`. Any other result is
`E_CALIBRATION_FAILED` and the verifier cannot activate.

## 3. Turn incidents into permanent gates

Every incident is recorded as:

`incident → failure code → invariant → reproducer → mutation → regression gate → owner`

```powershell
factory first-lap incident incident.json --root . --promote --json
```

The append-only ledger is `.factory/incidents/ledger.jsonl`; the promoted,
human-owned regression gate is written beneath
`.factory/incidents/promoted/`. Missing any link is rejected.

## 4. Verify holdouts and the observed lap

```powershell
factory first-lap holdout holdout-binding.json --root . --json
factory first-lap observe observed-events.json --json
factory first-lap verify --root . --calibration calibration.json --holdout holdout-boundary.json --observed observed-first-lap.json --json
```

The phases are strict and ordered:

`intake → candidate_binding → validation → failure_handling → cleanup → handoff`

The resulting activation receipt is supervised only; it never approves,
merges, publishes, deploys, signs, or discovers credentials.

## 5. Retry only what is safe to retry

```powershell
factory first-lap failure transient_provider_failure --provider openvsx --retry-after 10
```

Only narrowly classified transient provider failures may be retried. Product
failures, stale evidence, unverifiable candidates, and environment/setup
failures remain human-review events.

## Governance boundary

First Lap composes existing Oracle Firewall, candidate-lineage, Gauntlet,
Proof-Delta, Graph Ops, and session-recorder facts. It is an activation
boundary, not a replacement for those verifiers and not a claim of isolation,
semantic correctness, store approval, or production readiness. Human release
authority remains explicit.
