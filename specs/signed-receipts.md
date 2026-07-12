# Spec: signed-receipts
Status: approved

## MUST - Functional core
### Description
Authenticate existing factory receipt files with Sigstore keyless signatures so
a developer can prove which OIDC identity signed the exact receipt bytes.

### User roles
- Developer
- Maintainer
- Verifier

### Requirements (EARS)
- The system shall reject a signing request unless the input is a JSON object whose schema begins with `factory.receipt.`.
- When `receipts/build.json` is accepted for signing, the system shall execute `sigstore sign receipts/build.json` with a timeout of 300 seconds and return `receipts/build.json.sigstore.json`.
- If the Sigstore command is unavailable, the system shall return a non-zero result containing `E_SIGSTORE_UNAVAILABLE` and the install command `pip install factoryline-code-factory[sigstore]`.
- If the Sigstore signing command returns a non-zero result or no bundle file, the system shall return a non-zero result containing `E_SIGNING_FAILED`.
- If a verification request omits the expected certificate identity or expected OIDC issuer, the system shall reject the request with `E_IDENTITY_REQUIRED` before executing Sigstore verification.
- When Sigstore verifies the receipt bytes, certificate identity, OIDC issuer, certificate chain, and transparency evidence, the system shall return `SIGSTORE_IDENTITY_VERIFIED` with verification method `sigstore_identity`.
- If receipt bytes, certificate identity, OIDC issuer, signature, or transparency evidence do not verify, the system shall return a non-zero result containing `E_VERIFICATION_FAILED`.
- The system shall emit `factory.sigstore.result.v1` JSON containing receipt path, bundle path, expected identity, expected issuer, verification method, and verdict without copying receipt contents.
- When a valid receipt has no Sigstore bundle sidecar, the system shall return `UNSIGNED` rather than `VERIFIED`.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: CI signs and verifies a real receipt
  Given `receipts/build.json` has a schema beginning with `factory.receipt.`
  And the expected certificate identity and expected OIDC issuer are provided
  When `sigstore sign receipts/build.json` completes within 300 seconds
  Then `receipts/build.json.sigstore.json` is created
  And Sigstore verifies receipt bytes, certificate identity, OIDC issuer, certificate chain, and transparency evidence
  And verification returns `SIGSTORE_IDENTITY_VERIFIED`
  And verification method is `sigstore_identity`
  And `factory.sigstore.result.v1` JSON contains receipt path, bundle path, expected identity, expected issuer, verification method, and verdict
  And JSON output does not contain receipt contents

Scenario: expected signer data is mandatory
  Given a valid receipt and Sigstore bundle sidecar
  When expected certificate identity or expected OIDC issuer is omitted
  Then the request is rejected with `E_IDENTITY_REQUIRED` before Sigstore verification

Scenario: missing Sigstore fails with an install action
  Given `receipts/build.json` has a schema beginning with `factory.receipt.`
  When the Sigstore command is unavailable
  Then the command returns `E_SIGSTORE_UNAVAILABLE`
  And the command prints `pip install factoryline-code-factory[sigstore]`

Scenario: signing failure is closed
  Given `receipts/build.json` has a schema beginning with `factory.receipt.`
  When Sigstore returns non-zero or creates no bundle file
  Then the command returns `E_SIGNING_FAILED` with a non-zero result

Scenario: unsigned evidence remains explicit
  Given a valid receipt has no Sigstore bundle sidecar
  When receipt status is requested
  Then the command returns `UNSIGNED` and does not return `VERIFIED`

Scenario: changed receipt bytes are rejected
  Given a receipt with a valid Sigstore bundle
  When one receipt byte changes after signing
  Then verification returns E_VERIFICATION_FAILED with a non-zero result

Scenario: identity substitution is rejected
  Given a receipt signed by workflow identity A
  When verification requires workflow identity B
  Then verification returns E_VERIFICATION_FAILED with a non-zero result
```

## SHOULD - Technical and structural
- Dependency: `sigstore` remains an optional package extra.
- Integration: the CLI delegates cryptography, certificate validation, and transparency verification to the official Sigstore client.
- Output: signing produces the standard Sigstore bundle sidecar.

## SHOULD NOT - Implementation details
- The system shall not call a hash chain a signature.
- The system shall not infer the expected signer identity from the receipt payload.
- The system shall not store OIDC tokens in receipts, logs, or bundles.
- The system shall not claim offline verification in this release.
