# Intent-Bound Audit Admission

An intake envelope records the human-confirmed operating limits for a run. The
admission boundary makes those limits executable as a compatibility check: the
runtime audit plan, external-agent packet, Proof Review, and release preflight
must match the same envelope digest before they can be consumed.

## What is checked

- the envelope is current, self-hash-valid, source-bound, and `READY`;
- every consumer digest matches `parameter_sha256`;
- requested paths stay inside the sealed scope;
- runtime plans retain all six audit lanes;
- budgets never exceed the sealed caps;
- autonomy and external-effects posture do not drift;
- consumer expiry never outlives the intake envelope.

Any mismatch is read-only and fail-closed. The stable markers are
`E_INTAKE_PARAMETER_DRIFT`, `E_INTAKE_BINDING_SCOPE_ESCAPE`,
`E_INTAKE_BINDING_LANES_MISMATCH`, `E_INTAKE_BINDING_BUDGET_INVALID`,
`E_INTAKE_BINDING_MODE_MISMATCH`, `E_INTAKE_BINDING_EXTERNAL_EFFECTS_MISMATCH`,
`E_INTAKE_BINDING_EXPIRY_MISMATCH`, and `E_INTAKE_BINDING_REQUIRED`.

## Checkpoint fixes

An agent may be given a checkpoint fix allowance only as part of an admission
request that declares `write_workspace`. The allowance binds a checkpoint ID,
workspace-relative target paths, a hash-checked patch artifact, a reason, and a
named approval whose expiry covers the run. `factory` validates and reports the
allowance as `BOUND_FOR_EXTERNAL_HARNESS`; it never applies the patch. The
harness must revalidate the packet immediately before use, and the intake
digest, scope, budgets, and negative cases remain immutable.

## Operator path

```powershell
factory runtime-audit inspect plan.json --trust-root keys/trust-root.json `
  --trust-root-sha256 <sha256> --environment-sha256 <sha256> --require-intake --json
factory admission prepare passport.json request.json --root . --require-intake --json
factory proof-review quick --root . --id review-1 --contract contract.json `
  --changed src/service.py --intake-parameters .factory/intake-parameters/demo/receipt.json `
  --require-intake --json
factory release preflight --root . --contract release.json `
  --intake-parameters .factory/intake-parameters/demo/receipt.json --require-intake --json
```

The complete proof chain is:

`human intent → intake parameters → admitted plan → six lanes → evidence → decision`.

This is local proof only. It does not run providers, apply repairs, approve
work, publish, deploy, or grant credentials.
