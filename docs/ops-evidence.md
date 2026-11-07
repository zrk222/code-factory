# Local evidence workflows

These commands join existing CF checks. They do not merge, publish, or approve a release.

## Pre-PR verification

```sh
factory change pre-pr pre-pr.json --root . --json
factory change pre-pr pre-pr.json --root . --execute --out pre-pr-receipt.json --json
```

The `factory.pre-pr.v1` manifest contains `feature`, `base`, exact `head_sha`,
`schedule`, `live`, and `oracle`. `schedule` uses the existing
`factory.incremental-plan.v1` schema; `live` uses `factory.live-feedback.v1`.
Both must name the actual Git changes, and their gate/check IDs must match.
`oracle` names workspace-relative `contract`, `challenge`, and `result` JSON files.
The live contract digest must match the verified oracle and the feature's strict
release contract. Existing feature gate receipts must also verify.

Scheduled checks run through isolated replay only with `--execute`. Failed
dependencies stop downstream checks. Missing, stale, skipped, or unexecuted
obligations cannot produce PASS. The receipt retains underlying diagnostics,
source identity, oracle verification, and an advisory GitHub review payload.

Reuse additionally requires the same command, environment, expected successful
exit, dependency files, and acceptance profile. In the proof gate's `toolchain`,
`pre_pr_check_sha256` is the SHA-256 of canonical UTF-8 JSON (sorted keys, compact
separators, non-ASCII preserved) containing:

```json
{"check": "the normalized live check object", "contract_sha256": "the live contract digest", "assurance_level": "the schedule assurance level"}
```

Obtain the normalized check from `validate_live_manifest`; hash the object, not
the descriptive strings above. Missing or mismatched bindings require execution.
Reuse is checked again at consumption and final reconciliation.

## Repair continuity

```sh
factory senior fix repair.json --root . --execute --out .factory/attempt-2.json \
  --prior-attempt .factory/attempt-1.json --max-rounds 3 --json
```

Repeat `--prior-attempt` in oldest-first order. CF validates the entire supplied
chain against the original failure, controls, contract, and candidate. A repeated
failed candidate returns `NO_PROGRESS`; the default budget stops before a fourth
executed attempt with `STEP_BACK`. Planning consumes no executed rounds. Omitted
history starts a new local chain; hashes provide consistency, not signer identity.
Branch-comparison manifests currently accept neither history nor a custom budget.

## Reviewed incident intake

```sh
factory senior incident incident.json --root . --out regression.json --json
```

The `factory.incident-regression-intake.v1` manifest supplies `packet_id`, original
`events`, `group_fingerprint`, a `replay` manifest, at least one `controls` manifest,
and `review` containing `review_id` and `reviewer`. CF recomputes triage and checks
current source/input hashes and matching contracts. Identical controls coalesce;
conflicting replay IDs are rejected. Review identity remains a caller assertion.

The output is `EXPOSED_NOT_EXECUTED`: an input for existing regression tooling,
not an execution result or an untouched held-out sample.
