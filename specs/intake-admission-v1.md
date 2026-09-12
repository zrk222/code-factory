# Spec: intake-admission-v1

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

Every strict consumer of a Code Factory audit must be able to prove that its
scope, lanes, budget, autonomy, effects, expiry, and digest are compatible with
one authoritative intake-parameter envelope.

### Declared facts

- `factory.intake-binding.v1` is a read-only compatibility receipt.
- Only an intake receipt with `status=READY` and a valid self-hash is
  authoritative; `REVIEW_REQUIRED` is advisory and cannot admit work.
- Runtime audit plans may bind `{path, parameter_sha256, external_effects}`
  and must retain the canonical six lanes.
- Run admission requests may bind `{path, parameter_sha256}` and may carry a
  human-approved, hash-bound checkpoint fix; the fix is never applied by CF.
- Proof Review and release preflight may bind an authoritative intake receipt
  and must reject changed scope or digest.
- Strict consumers return stable `E_INTAKE_*` errors before execution or
  provider interaction.

### Data model and markers

- `READY` is the authoritative intake state; `REVIEW_REQUIRED` is advisory.
- A strict consumer marker names the exact mismatch or allowance outcome; the
  requirements below declare the markers so validator mutation can trace them.
- `expiry` is a UTC RFC3339 timestamp and every consumer expiry must be no later
  than the envelope expiry; the canonical audit set contains six named lanes.

### Requirements (EARS)

- When a strict consumer supplies a current authoritative envelope binding, verification shall return `INTAKE_BINDING_VERIFIED`.
- If strict mode is requested and the binding is missing, the consumer shall return `E_INTAKE_BINDING_REQUIRED`.
- If scope, lane, budget, mode, effects, expiry, or digest differs, the consumer shall return `E_INTAKE_BINDING_SCOPE_ESCAPE` or another specific intake-binding mismatch marker and shall not start execution.
- If the envelope is advisory, past its UTC RFC3339 expiry, tampered, or source-drifted, the consumer shall return `E_INTAKE_BINDING_ADVISORY` or `E_INTAKE_PARAMETER_DRIFT` and shall not admit work.
- If a checkpoint fix is requested, the consumer shall report `BOUND_FOR_EXTERNAL_HARNESS` only after requiring `write_workspace`, a hash-matching patch artifact, in-scope paths, a named approval, and an expiry covering the run, without applying the patch.

## SHOULD NOT - Non-goals

- No provider, network, credential, execution, patch application, publication,
  deployment, merge, or approval authority.
- No claim that an authoritative parameter is correct beyond its source and
  human confirmation; independent validators still decide evidence quality.

## Acceptance criteria

```gherkin
Scenario: Admit a matching strict runtime plan
  Given a READY intake envelope and a signed six-lane plan
  When the plan digest, scope, effects, expiry, and budget are checked
  Then verification returns INTAKE_BINDING_VERIFIED

Scenario: Refuse an oracle-like weakening through intake drift
  Given a plan widens a sealed scope or budget
  When the plan is inspected
  Then verification returns E_INTAKE_BINDING_SCOPE_ESCAPE before execution

Scenario: Permit a bounded checkpoint fix without granting execution
  Given a write_workspace admission with a named approval and hash-bound patch
  When the packet is verified
  Then the fix is reported BOUND_FOR_EXTERNAL_HARNESS and no patch is applied

Scenario: Refuse advisory intake
  Given an envelope contains an agent-proposed parameter
  When a consumer attempts admission
  Then it returns E_INTAKE_BINDING_ADVISORY

Scenario: Keep every admission requirement observable
  Given the intake-admission-v1 contract
  When strict validator mutation checks each requirement
  Then the contract markers include INTAKE_BINDING_VERIFIED, E_INTAKE_BINDING_REQUIRED, E_INTAKE_BINDING_SCOPE_ESCAPE, E_INTAKE_BINDING_ADVISORY, E_INTAKE_PARAMETER_DRIFT, and BOUND_FOR_EXTERNAL_HARNESS
```
