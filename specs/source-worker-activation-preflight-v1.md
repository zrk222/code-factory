# Spec: source-worker-activation-preflight-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Agent Oven shall provide a fail-closed, provider-neutral activation preflight for the authoritative-source worker. The preflight shall validate short-lived workload-token claims, prove every configured opaque source reference resolves, optionally observe live identity and source-secret rotation, and emit only a redacted receipt. Convex remains the signature-verifying authority.

### Requirements (EARS)

- If `ACTIVATION_CONFIGURATION_MISSING` omits expected issuer, audience, subject, or source-reference configuration, the preflight shall reject with `E_SOURCE_WORKER_ACTIVATION_CONFIG_MISSING` before credential access.
- If `ACTIVATION_CONFIGURATION_INVALID` contains an issuer, audience, or subject outside 1 through 512 characters, malformed source-reference JSON, a source-reference count outside 1 through 32, an invalid closed source reference, or a rotation duration outside integer seconds 5 through 300, the preflight shall reject with `E_SOURCE_WORKER_ACTIVATION_CONFIG_INVALID` before credential access.
- When `ACTIVATION_CONFIGURATION_VALID` contains issuer, audience, and subject strings of 1 through 512 characters plus a JSON array of 1 through 32 source references, the preflight shall return a normalized activation policy without credential values.
- If `ACTIVATION_STATIC_IDENTITY_SELECTED` uses `static-development` identity mode, the preflight shall reject with `E_SOURCE_WORKER_PRODUCTION_IDENTITY_REQUIRED` before source resolution.
- If `ACTIVATION_TOKEN_MALFORMED` is not three non-empty base64url segments containing a JSON object payload, the preflight shall reject with `E_SOURCE_WORKER_IDENTITY_CLAIMS_INVALID`.
- If `ACTIVATION_TOKEN_ISSUER_MISMATCH` contains an `iss` value other than the configured issuer, the preflight shall reject with `E_SOURCE_WORKER_IDENTITY_ISSUER_MISMATCH`.
- If `ACTIVATION_TOKEN_AUDIENCE_MISMATCH` contains neither an `aud` string nor an `aud` array containing the configured audience, the preflight shall reject with `E_SOURCE_WORKER_IDENTITY_AUDIENCE_MISMATCH`.
- If `ACTIVATION_TOKEN_SUBJECT_MISMATCH` contains a `sub` value other than the configured subject, the preflight shall reject with `E_SOURCE_WORKER_IDENTITY_SUBJECT_MISMATCH`.
- If `ACTIVATION_TOKEN_TIME_INVALID` contains a non-integer `exp`, an `exp` less than the current epoch second plus 120, an `nbf` greater than the current epoch second plus 30, or an `iat` greater than the current epoch second plus 30, the preflight shall reject with `E_SOURCE_WORKER_IDENTITY_TIME_INVALID`.
- When `ACTIVATION_PREFLIGHT_READY` has valid claims and all 1 through 32 configured references resolve to non-empty bounded values, the preflight shall return receipt schema version `1`, status `ready`, the checked epoch second, reference count, `signatureVerified: false`, and `requiresControlPlaneVerification: true`.
- When `ACTIVATION_RECEIPT_REDACTED` is created, the preflight shall return a serialized receipt object containing none of the token bytes, JWT claims, issuer, audience, subject, source references, resolved values, filesystem paths, or value fingerprints.
- When `ACTIVATION_ROTATION_DRILL_SUCCEEDS` observes a changed identity fingerprint and changed fingerprints for all configured source references within 5 through 300 seconds, the drill shall return status `rotated`, a sample count of at least 2, `identityRotated: true`, and the number of rotated references.
- If `ACTIVATION_ROTATION_DRILL_TIMES_OUT` reaches exactly its configured integer duration from 5 through 300 seconds without both identity rotation and rotation of every configured source reference, the drill shall reject with `E_SOURCE_WORKER_ROTATION_NOT_OBSERVED` and return no receipt.
- If `ACTIVATION_REFERENCE_UNRESOLVED` occurs for any configured reference, the preflight shall reject with the unchanged closed resolver error and return no ready receipt.
- When `ACTIVATION_COMMAND_SUCCEEDS` occurs, the command shall write exactly one redacted JSON receipt line to standard output and exit with status `0`.
- If `ACTIVATION_COMMAND_FAILS` occurs, the command shall write exactly one closed `E_SOURCE_WORKER_*` code line to standard error, write no standard output, and exit with status `1`.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: A valid production identity passes preflight without becoming trusted locally
  Given a rotating-file JWT whose issuer, audience, subject, and time claims satisfy the activation policy
  And every configured closed source reference resolves
  When the activation preflight runs
  Then the receipt status is ready
  And signatureVerified is false
  And requiresControlPlaneVerification is true
  And no credential, claim, reference, path, or fingerprint is serialized

Scenario: External rotation becomes observable
  Given a ready activation snapshot
  And the projected identity and every configured source secret rotate within 300 seconds
  When the rotation drill samples the worker boundary
  Then the drill receipt status is rotated
  And identityRotated is true
  And rotatedReferences equals the configured reference count
```

## SHOULD - Technical and structural

- Keep claim and rotation decisions injectable and deterministic in tests.
- Keep Node base64url decoding, SHA-256, file reads, environment reads, output, and process exit inside the command adapter.
- Reuse the existing identity provider and closed source-reference resolver.

## SHOULD NOT - Implementation details

- Do not treat decoded JWT claims as signature verification.
- Do not write secret-derived hashes or stable reference identifiers into receipts.
- Do not add a cloud-provider SDK to the worker.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `ACTIVATION_CONFIGURATION_MISSING` | reject before credential access |
| 2 | `ACTIVATION_CONFIGURATION_INVALID` | reject with `E_SOURCE_WORKER_ACTIVATION_CONFIG_INVALID` |
| 3 | `ACTIVATION_CONFIGURATION_VALID` | return a normalized secret-free policy |
| 4 | `ACTIVATION_STATIC_IDENTITY_SELECTED` | reject static identity for production activation |
| 5 | `ACTIVATION_TOKEN_MALFORMED` | reject malformed claims |
| 6 | `ACTIVATION_TOKEN_ISSUER_MISMATCH` | reject issuer mismatch |
| 7 | `ACTIVATION_TOKEN_AUDIENCE_MISMATCH` | reject audience mismatch |
| 8 | `ACTIVATION_TOKEN_SUBJECT_MISMATCH` | reject subject mismatch |
| 9 | `ACTIVATION_TOKEN_TIME_INVALID` | reject invalid time bounds |
| 10 | `ACTIVATION_PREFLIGHT_READY` | return a redacted non-signature-verifying receipt |
| 11 | `ACTIVATION_RECEIPT_REDACTED` | omit all credential and stable secret metadata |
| 12 | `ACTIVATION_ROTATION_DRILL_SUCCEEDS` | return a bounded rotation receipt |
| 13 | `ACTIVATION_ROTATION_DRILL_TIMES_OUT` | reject without secret output |
| 14 | `ACTIVATION_REFERENCE_UNRESOLVED` | fail closed through the existing resolver |
| 15 | `ACTIVATION_COMMAND_SUCCEEDS` | emit one receipt and exit 0 |
| 16 | `ACTIVATION_COMMAND_FAILS` | emit one error code and exit 1 |
