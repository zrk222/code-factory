# Spec: deep-audit-attestation-v1

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

Deep-audit findings must be consumable as current evidence only when an
independent verifier has signed the exact receipt and the signed observation is
inside a bounded freshness window. A receipt self-hash alone is insufficient.

### Declared facts

- `factory.deep-audit-attestation.v1` is an externally produced DSSE document;
  Code Factory verifies it offline against an operator-pinned trust root.
- The attestation binds one self-hash-valid deep-audit receipt, its candidate,
  signed plan, ruleset, canary set, and complete target/canary report hashes.
- The verifier must be explicitly independent and must not reuse an analyzer id.
- `issued_at` and `expires_at` are timezone-aware UTC instants; the attestation
  is valid for at most 24 hours and the current observation age defaults to at
  most 3600 seconds.
- Verification is review-only. It does not run analyzers, apply repairs,
  approve, merge, publish, deploy, or grant credentials.

### Requirements (EARS)

- The system shall verify `REQ_ATTESTATION_BINDING` by checking the signed DSSE envelope, signer identity, `factory.deep-audit-attestation.v1` payload schema, receipt/plan/candidate/ruleset/canary digests, complete report and canary coverage, independent verifier identity, timezone-aware `issued_at` and `expires_at`, and the 3600 seconds age plus 86400 seconds validity bounds; it shall return `DEEP_AUDIT_ATTESTATION_VERIFIED` for matching fresh evidence, return `E_DEEP_ATTESTATION_SIGNATURE`, `E_DEEP_ATTESTATION_SCHEMA`, or `E_DEEP_ATTESTATION_BINDING` before comparison for invalid signed content, return `E_DEEP_ATTESTATION_INDEPENDENCE` for an analyzer-self verifier, return `E_DEEP_ATTESTATION_FRESHNESS` for future, expired, stale, or overlong evidence, return `E_DEEP_ATTESTATION_REQUIRED` when strict comparison lacks both attestations or its pinned trust root, and return verified identity and freshness facts with `authority: none` without changing repair state.

## SHOULD NOT - Non-goals

- No analyzer execution, network lookup, key discovery, patch application,
  automatic retry, approval, release, deployment, or credential access.
- No claim that a signed receipt proves the analyzer's semantic correctness or
  that no defects remain.

## Deterministic implementation bounds

- Attestation, verifier, and analyzer identity strings are limited to 256
  characters; timestamp text is limited to 40 characters and `Z` maps to the
  UTC offset `+00:00`.
- `max_age_seconds` is an integer from 1 through 86400; report and canary maps
  contain 1 through 8 analyzer entries and every value is a lowercase SHA-256
  digest.
- Existing read-only lineage compatibility remains bounded to 50 finding
  chains and uses the first location at index 0; these bounds do not grant
  authority or change repair state.

## Acceptance criteria

```gherkin
Scenario: Verify a fresh independent deep-audit attestation
  Given REQ_ATTESTATION_BINDING is applied to a self-hash-valid deep-audit receipt and an offline DSSE trust root
  When an independent verifier signs matching plan, candidate, rules, canaries, and reports
  Then verification returns DEEP_AUDIT_ATTESTATION_VERIFIED

Scenario: Reject stale or future attestation evidence
  Given a signed attestation outside the 3600-second age window or issued after the current instant
  When it is verified
  Then it returns E_DEEP_ATTESTATION_FRESHNESS

Scenario: Reject analyzer self-attestation
  Given a verifier id equal to one of the signed analyzer ids
  When it is verified
  Then it returns E_DEEP_ATTESTATION_INDEPENDENCE

Scenario: Require signed evidence for strict comparison
  Given deep-audit comparison is run with strict attestation enabled
  When either receipt attestation or the trust root is missing
  Then it returns E_DEEP_ATTESTATION_REQUIRED without reading provider state

Scenario: Keep the signed chain review-only
  Given a valid attestation pair
  When comparison completes
  Then authority remains none and no analyzer, repair, approval, or release action runs
```
