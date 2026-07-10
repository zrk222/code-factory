# Failure Attribution

The factory reports which build-time unit failed, its stable failure class, and
concrete evidence. Attribution explains a gate verdict; it never changes it.

```text
specline:strict      0.83 (10/12)  ambiguous_requirement
forgeline:smoke      0.50 ( 2/4 )  runtime_timeout
forgeline:verify_tests 0.67 (2/3)  hollow_test
hsf:accuracy         0.93 (37/40)  wrong_output
```

Factoryline recommends the earliest failing stage because downstream failures
may be consequences of an upstream defect. Refinement is deterministic: one
localized edit, structural before configuration before parameter tuning, exact
Pareto acceptance, and a stop after two consecutive non-wins.

## H=0 Boundary

Attribution, refinement state, edit selection, and rejection ledgers are
build-time only. They live in `.factory/`, `.forge/`, or `receipts/`, never in
`registry/`. Compiled artifacts contain none of those symbols.

The loop learns; the artifact does not drift.

## Reverse-Classical Test Verification

ForgeLine `verify_tests` uses two additional stable classes:

- `hollow_test`: a behavioral smoke check passed against the generated empty
  SSAT scaffold, so it asserts nothing the implementation provides.
- `hollow_manifest`: the smoke manifest has no behavioral proof, for example
  every check is explicitly exempt from failing on the stub.

Both are build-time attribution only. They guide structural test rewrites and
roll up like any other ForgeLine gate.
