# Whole-run sequence evidence

A real `factory assemble FEATURE` declares an ordered plan before executing
its stages. Before each planned native stage, assembly writes an intent.
After the native receipt is written, assembly records the outcome and binds
it to the receipt and intent by SHA-256. The native receipt records the run
ID, manifest digest and position. An evidence write failure halts the run
with `SEQUENCE_EVIDENCE_ERROR`.

The plan includes required stages and applicable optional stages. An
unavailable companion can be skipped only when its gate is outside the
feature scope. Existing design or compile receipts also declare scope. Paused and failed runs retain their partial
evidence. Dry runs and historical workspaces receive no new sequence evidence.

## Verify readiness

```sh
factory verify FEATURE --root WORKSPACE --json
factory verify FEATURE --root WORKSPACE --sequence-run-id RUN_ID --json
```

By default, verification picks the newest plan that covers every required
stage. It blocks readiness if that run is incomplete, failed or unverifiable.
If any required stage's latest receipt is outside the passing basis,
verification reports `SEQUENCE_BASIS_SUPERSEDED`. A subset plan cannot
become the basis, but the receipts it writes still count as current evidence.

Without a recorded whole-run plan, verification reports gate-only
readiness and `whole_run.assured=false`. Adding a required gate after a whole run
requires a new whole run that covers that gate. The release decision card and
release-contract projection report `whole_run_assured`, `whole_run_basis`
and `whole_run_limit`.

Passing `--sequence-run-id` enables strict selected-run verification.
It checks the selected receipts, ship intent and any applicable
`--strict-release` contract bindings. Normal latest-stage gate failures
also block the result. Mission completion can verify its exact ship-only
handoff while release readiness still requires one current whole run.

## Recover damaged evidence

An unreadable or malformed manifest, stray inventory entry or symlink blocks
default verification. To quarantine an unverifiable run directory, use:

```sh
factory sequence quarantine FEATURE RUN_ID --root WORKSPACE --reason "Explain the damage"
```

This writes a one-way `quarantine.json` marker and preserves the original
evidence. Verification lists the quarantined run and still checks the
receipts it wrote. When no eligible basis remains, run a new whole assembly.

## Evidence boundary

Run manifests and position records live in
`.factory/run-sequences/FEATURE/RUN_ID/`. The evidence represents local
producer assertions. Names that require encoding use a deterministic
directory name and retain the original feature name in the records. Hashes bind evidence content and local timestamps
order the records. The records cannot establish signer identity, trusted
time, independent execution or provider effects.
