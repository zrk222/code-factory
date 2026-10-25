# Plan: jev-informed-inputs-v1
Spec: specs/jev-informed-inputs-v1.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Shared source-linked native sink evidence with scope and binding checks.
2. Deterministic packet validation and bounded source expansion for JEV.
3. Frozen repaired-family diagnosis, then independent fresh evaluation.

## Tasks (atomic — independently reviewable)
- [ ] T1 | slice=factoryline | files=factoryline/finite_capture.py,factoryline/runtime_audit_integrity.py,tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k sink_context -q` | Capture observed sink expressions, definitions, bindings, enclosing scope and explicit unknowns using existing AST and source indexes. No new production module.
- [ ] T2 | slice=factoryline | files=factoryline/analysis_evidence.py,factoryline/jev_classifier.py,tests/test_audit_rule_search.py | verify=`python -m pytest tests/test_audit_rule_search.py -k informed -q` | Resolve bounded captured helpers/callers and format the shared evidence for secondary review; do not invent missing authority or execute code.
- [ ] T3 | slice=scripts | files=scripts/evaluate_jev.mjs,scripts/evaluate_jev.test.mjs | verify=`node --test --test-name-pattern=informed scripts/evaluate_jev.test.mjs` | Enforce strict references and evidence states, reject source drift and label leakage, preserve native outcomes.

- [ ] T4 | slice=factoryline | files=factoryline/semantic_credential_sensor.py,tests/test_semantic_credential_sensor.py | verify=`python -m pytest tests/test_semantic_credential_sensor.py -k sink_context -q` | Resolve the modeled Flask body-reader call shape and bytes/text source kind through existing source-bound request and call-binding validators; retain malformed, unknown and replaced providers.

## Acceptance and measurement
The original Study287 results (36 abstentions, 1 input-bound unassessed) remain
immutable. Freeze the new source builder, rubric and same-family inputs before
rerun. Keep labels outside requests. Report native raw finding precision and
secondary recommendation precision separately with actual positive denominator,
TP retention, uncertainty-inclusive coverage and all input errors. This is exposed
development diagnosis, not a fresh holdout. Meet the complete original release
and accuracy requirements on an independently frozen fresh cohort afterward.

## Current boundaries
No target imports/execution, publication or release. Provider access is explicit,
locally encrypted, short-lived and quota-bound. Native CF validators remain the
primary decision path when JEV is absent or disagrees.
