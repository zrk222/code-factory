# Six-Module Release Hardening

This upgrade makes the Code Factory control plane reject an attractive but
unsafe outcome: a green local summary produced from incomplete, malformed,
stale, cross-platform, or self-declared evidence.

## Control path

`source -> approved obligation -> forbidden behavior -> gate -> test -> evidence -> decision`

The release decision is local and bounded. It does not authenticate a person,
run a missing tool, access a provider, upload a build, sign an artifact, or
guarantee external approval.

| Slice | Enforced behavior | Deterministic evidence |
| --- | --- | --- |
| Receipt integrity | `ok` must be a JSON boolean; changed or malformed receipts remain visible blockers. | Stable-read receipt snapshot and schema validation. |
| Shared approval authority | Strict local release checks require a hash-valid release contract bound to a current Oracle contract. | `factory.release-contract.v1`; policy digest; Oracle verification. |
| Bounded execution | Process output, time, interruption, and cleanup are bounded. This is process hygiene, not a sandbox claim. | `assembly_process.run_cli` tests. |
| UI and mobile truth | A declared design/compiler gate cannot be skipped because an input file is missing; iOS and Android evidence is evaluated separately. | Release-contract stage declaration; AppForge per-platform reports. |
| Evidence operations | Newest evidence wins deterministically; unavailable or invalid evidence remains visible and masks older READY state. | mtime/path ordering, bounded stable reads, invalid/truncation counts, replay verification. |
| Release train | CI uses pinned companion revisions and exercises incomplete, strict-bound, and stale-receipt cases from the built wheel. | `scripts/release_train_e2e.py`. |

## Operator workflow

1. Seal original intent and sources with the Oracle Firewall.
2. Run the normal SpecLine, ForgeLine, optional Prestige/HSF, and explicit
   AppForge gates for the approved scope.
3. For a strict local decision, generate a reviewed release contract from the
   sealed Oracle. The helper computes the canonical policy digest and refuses
   to overwrite an existing contract:

```powershell
factory release-contract template <feature> --root . `
  --oracle-contract .factory/oracles/contracts/<feature>.json `
  --approved-by "Named reviewer" `
  --out .factory/release-contracts/<feature>.json
```

Add `--stage prestige:score` or `--stage hsf:compile` when those gates are in
scope. For AppForge, bind the replayable receipt explicitly:
`--stage appforge:mobile-evidence --evidence appforge:mobile-evidence=.factory/appforge/mobile-evidence.json`.
The resulting contract has this shape:

```json
{
  "schema": "factory.release-contract.v1",
  "feature": "<feature>",
  "oracle_contract": ".factory/oracles/contracts/<feature>.json",
  "oracle_contract_sha256": "<current Oracle contract digest>",
  "required_stages": [
    "specline:strict", "specline:verify-validators", "specline:gate-spec",
    "specline:tasks", "specline:gate-plan", "forgeline:architect",
    "forgeline:review", "forgeline:arch-gate", "forgeline:verify-tests",
    "forgeline:smoke", "forgeline:ship"
  ],
  "approved_by": "<named reviewer>",
  "policy_digest": "<canonical JSON digest excluding this field>"
}
```

4. Verify the contract itself when needed with
   `factory release-contract verify <feature> .factory/release-contracts/<feature>.json --root . --json`.
5. Run `factory verify <feature> --root . --strict-release --json`.
6. Treat `STRICT LOCAL GATES PASS` as a local evidence decision only. Complete signing,
   provider upload, deployment, submission, and external read-back through
   their separate authorized workflows.

## Claim boundary

The hardening prevents a local promotion decision from treating missing or
malformed evidence as a pass. It cannot prove an LLM understood an unprovided
intent, make a supplied report truthful, or replace independent security,
device, provider, and human review.
