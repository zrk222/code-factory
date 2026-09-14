# Spec: runtime-attestation-isolation-v1

Status: draft
SpecFactor-target: 0.75-2.5

## Outcome

Code Factory shall make the runtime boundary a first-class, reviewable result
alongside the six audit lanes. A local supervised process must remain labelled
as supervised-only; an independent isolation claim must be backed by a fresh,
hash-bound observation from a matching external backend. Neither result grants
release authority.

## MUST - Boundary contract

### Declared outputs and values

- The payload schema is `factory.runtime-boundary-attestation.v1`, the join
  decision schema is `factory.runtime-boundary-decision.v1`, and the signed
  verification receipt schema is `factory.runtime-boundary-verification.v1`.
- Closed findings include `E_RUNTIME_ATTESTATION_MISSING`,
  `E_ATTESTATION_BINDING`, `E_ATTESTATION_SELF_HASH`,
  `E_ATTESTATION_FRESHNESS`, and `E_ISOLATION_UNPROVEN`.
- `DSSE` means the existing offline signed-envelope format; `VERIFIED` is a
  review-only state and never an approval.

### Requirements (EARS)

- When `R10` `RUNTIME_BOUNDARY_PLAN` is present in a signed six-lane plan, it shall return an accepted contract only for exactly one requested isolation mode from `supervised_subprocess`, `isolated_worker`, or `hardened_vm` with `attestation_required=true`, and it shall reject any other shape with `E_RUNTIME_BOUNDARY`.
- When `R20` `RUNTIME_BOUNDARY_CAPTURE` runs through the local runner, it shall emit record shell=false, devnull stdin, hashed output streams, the minimal environment policy, executable digest, workspace-environment digest, cleanup, and resource observations; it shall return `SUPERVISED_ONLY` and shall not claim a sandbox.
- When `R30` `RUNTIME_BOUNDARY_VERIFY` receives an observation, it shall bind the candidate, plan, environment, executable, nonce, issue/expiry window, and self-hash; it shall reject shell=true, non-minimal environment policy, executable drift, stale/replayed observations, unknown fields, and missing cleanup.
- When `R40` `RUNTIME_BOUNDARY_VERIFY` evaluates `isolated_worker` or `hardened_vm`, it shall return `E_ISOLATION_UNPROVEN` unless a matching backend, `state=VERIFIED`, `proof=true`, and a non-local collector role are present; a local supervisor shall never self-attest that boundary.
- When `R50` `RUNTIME_BOUNDARY_JOIN` evaluates a plan requiring a boundary and observes a missing, mismatched, stale, or weaker observation, it shall return a composite six-lane decision of `BLOCKED` with the exact boundary finding; a supervised-only observation may accompany a supervised-subprocess request but is not an independent isolation proof.
- While `R60` any boundary receipt is returned, the system shall emit a boundary record retaining `authority=none` and `release_approval=false`; the boundary implementation shall not execute commands, contact providers, read credentials, or imply application correctness or store approval.

## Acceptance criteria

```gherkin
Scenario: local supervision is honest
  Given a six-lane plan requesting `R10` supervised_subprocess
  When the bounded runner captures its runtime facts
  Then the `R20` boundary result is SUPERVISED_ONLY
  And the claim boundary says no kernel, container, network, credential, or descendant isolation is proven

Scenario: independent isolation is not self-attested
  Given a six-lane plan requesting `R40` hardened_vm
  When only the local supervised runner observation is supplied
  Then the `R50` composite decision is BLOCKED with E_ISOLATION_UNPROVEN

Scenario: forged observation is rejected
  Given a `R30` boundary observation whose executable digest or self-hash changed
  When the observation is validated
  Then validation fails closed with E_ATTESTATION_BINDING or E_ATTESTATION_SELF_HASH

Scenario: signed external boundary is reviewable
  Given a fresh `R60` DSSE-signed observation from a matching hardened_vm collector
  When its trust root and bindings verify offline
  Then the result is VERIFIED
  And release_approval remains false
```

## SHOULD - Technical/structural

- Use `factory.runtime-boundary-attestation.v1` for the payload and
  `factory.runtime-boundary-decision.v1` for the six-lane join.
- Preserve only bounded hashes and categorical launcher facts; do not persist
  raw output, environment values, prompts, credentials, or process logs.
- Keep independent collector signing and host/container enforcement outside the
  local supervisor; the package verifies supplied evidence and reports gaps.

## MUST NOT - Claims

- No local process result is a kernel, container, VM, network, credential, or
  descendant-isolation proof.
- No attestation proves business intent, application correctness, production
  security, or external approval.
