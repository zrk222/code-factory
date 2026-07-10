# Failure Attribution

The factory reports which build-time unit failed, its stable failure class, and
concrete evidence. Attribution explains a gate verdict; it never changes it.

```text
specline:strict      0.83 (10/12)  ambiguous_requirement
specline:verify-validators 0.92 (11/12)  hollow_validator
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

The `hollow_test` guarantee is exact because ForgeLine materializes the mutant
with the same `scaffold_from_ssat` generator used by the normal `SCAFFOLDED`
state, and the regression suite checks the generated stub tree is byte-identical
to that scaffold. If that identity breaks, the reverse-classical gate is no
longer allowed to claim certainty.

Rollup recommendations use canonical pipeline order, not display order or
receipt timestamp order. `forgeline:verify_tests` precedes `forgeline:smoke`,
so a `hollow_test` dominates a downstream runtime failure in the same feature:
the instrument must be validated before the smoke result is trusted.

## Reverse-Classical Spec Verification

SpecLine `verify-validators` mutates one requirement at a time before the spec is
gated. It removes the requirement and, when possible, inverts a literal or bound.
The strict contract must reject those mutants. If a mutant still passes, the
requirement has no observable validator and reports `hollow_validator`.

This is the spec-level counterpart to `hollow_test`: a hollow test passes against
an empty implementation; a hollow validator passes against a mutilated spec.
Factory rollup treats `specline:verify-validators` as a structural failure after
`specline:strict` and before spec gate signoff or downstream ForgeLine stages.
