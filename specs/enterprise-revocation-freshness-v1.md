# Spec: enterprise-revocation-freshness-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Enterprise Receipt v2 verification shall make the freshness boundary of offline
revocation evidence explicit. Existing optional verification remains backward
compatible and historical-only; strict verification requires a signed,
timezone-aware revocation snapshot that is not future-dated and is no older
than the caller's bounded maximum age.

### User roles

- Security or policy operator publishing a signed revocation snapshot.
- Offline verifier checking a Receipt v2 envelope.
- Release reviewer consuming the structured decision and claim boundary.

### Declared facts

- `receipt_verified`: DSSE payload, signature, identity, issuer, and Receipt v2 schema verify against an explicit local trust root.
- `revocation_required`: strict mode requires a revocation snapshot; default mode preserves optional historical checking.
- `revocation_present`: a signed revocation snapshot was supplied to the verifier.
- `revocation_shape_valid`: the signed snapshot has a timezone-aware `generated_at`, bounded entries, and each entry identifies a `keyid` or `identity`; any supplied `revoked_at` is timezone-aware and valid.
- `revocation_current`: strict mode observes `0 <= now - generated_at <= max_age_seconds` with a timezone-aware caller time.
- `signer_not_revoked`: the signer was not revoked at or before the receipt timestamp.

### Requirements (EARS)

- When `REQ_STRICT_REVOCATION` verifies a Receipt v2 envelope, it shall require a signed `factory.revocations.v1` snapshot, validate its generation timestamp and entry shape, reject future or older-than-`max_age_seconds` snapshots with `E_REVOCATION_FRESHNESS`, reject missing input with `E_REVOCATION_REQUIRED`, reject malformed entries with `E_INVALID_REVOCATIONS`, return `revocation_status: FRESH_CHECKED`, `revocation_freshness: CURRENT`, and the bounded age when current, preserve `E_SIGNER_REVOKED` for a revoked signer, keep authority `none`, and perform no network or provider action. [R1]
- When `REQ_OPTIONAL_REVOCATION` verifies a supplied signed snapshot without strict mode, it shall preserve the historical signer check, return `revocation_status: CHECKED` with `revocation_freshness: NOT_ASSERTED`, and never represent the result as current hosted authorization. [R2]

### Acceptance criteria

```gherkin
Scenario: Strict verification requires current revocation evidence
  Given `REQ_STRICT_REVOCATION` has an explicit trust root
  When strict verification is requested without a revocation snapshot
  Then the result is E_REVOCATION_REQUIRED and no current result exists

Scenario: A current snapshot produces an explicit freshness fact
  Given a signed revocation snapshot generated 30 seconds before the supplied verifier time
  When strict verification allows an age of 60 seconds
  Then the result is FRESH_CHECKED with CURRENT freshness and age 30

Scenario: Stale or future snapshots fail closed
  Given a signed revocation snapshot older than the maximum or generated after the supplied verifier time
  When strict verification runs
  Then the result is E_REVOCATION_FRESHNESS

Scenario: Optional historical checking does not imply current authorization
  Given `REQ_OPTIONAL_REVOCATION` supplies a signed revocation snapshot without strict mode
  When verification succeeds
  Then the result is CHECKED with NOT_ASSERTED freshness

Scenario: Malformed signed entries are rejected
  Given a signed revocation snapshot contains an entry without a key identity or with an invalid revoked_at
  When verification runs
  Then the result is E_INVALID_REVOCATIONS
```

## SHOULD - Technical and structural

- API: `verify_receipt_v2(..., require_revocations=True, max_revocation_age_seconds=86400, now=...)` and `factory enterprise verify --require-revocations`.
- Freshness bounds are 1 through 604800 seconds; at most 4096 entries are accepted.
- The verifier remains offline, uses canonical JSON and existing DSSE trust roots, and emits no private key or receipt body.

## SHOULD NOT - Non-goals

- Do not perform network revocation discovery or claim hosted authorization freshness.
- Do not remove the backward-compatible optional mode.
- Do not grant execution, approval, release, publication, deployment, signing, or credential authority.

## Decision logic

| # | if | then |
|---|---|---|
| 1 | `revocation_required` is true and `revocation_present` is false | return `E_REVOCATION_REQUIRED` |
| 2 | `revocation_shape_valid` is false | return `E_INVALID_REVOCATIONS` |
| 3 | `revocation_current` is false | return `E_REVOCATION_FRESHNESS` |
| 4 | `signer_not_revoked` is false | return `E_SIGNER_REVOKED` |
| 5 | `receipt_verified`, `revocation_current`, and `signer_not_revoked` are true | return `FRESH_CHECKED` with authority `none` |
