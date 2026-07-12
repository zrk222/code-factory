# Spec: enterprise-receipt-v2
Status: proposed

## MUST - Functional core
### Description
Create an offline-verifiable enterprise evidence envelope without breaking
readability of existing factory receipt v1 JSON files.

### User roles
- Producer
- Policy administrator
- Offline verifier
- Revocation operator

### Requirements (EARS)
- The system shall emit canonical UTF-8 JSON with schema `factory.receipt.v2` and bind the exact payload bytes inside a DSSE envelope with payload type `application/vnd.factory.receipt.v2+json`.
- The system shall sign each envelope with `Ed25519` and include a non-empty key id, authenticated identity, and issuer in signature metadata.
- The system shall reject signing with `E_INVALID_RECEIPT` when the payload is not a Receipt v2 object, the private key is unavailable, or identity metadata is incomplete.
- The system shall verify `DSSEv1` pre-authentication encoding, signature, payload digest, trusted key id, authenticated identity, and issuer without network access, returning `VERIFIED` or `E_SIGNATURE_INVALID`.
- The system shall reject verification with `E_UNKNOWN_KEY` or `E_IDENTITY_MISMATCH` when the key id is unknown, the public key does not match, or the envelope has an unsupported signature.
- The system shall emit a signed policy bundle with schema `factory.policy.bundle.v1`, canonical policy bytes, and a `policy_sha256` digest bound in a DSSE envelope.
- When a Receipt v2 envelope declares a policy digest, the verifier shall reject it with `E_POLICY_DIGEST_MISMATCH` unless a verified policy bundle contains the exact same digest.
- The system shall emit signed revocation data with schema `factory.revocations.v1` and reject a receipt with `E_SIGNER_REVOKED` when its key id or identity is revoked at the receipt verification time.
- The system shall execute `offline` verification with zero network calls and return a structured fail-closed result with one declared error code for every rejection.
- The system shall return `LEGACY_UNVERIFIED` when the enterprise verifier receives a readable `factory.receipt.v1` JSON file.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: verify a valid Receipt v2 completely offline
  Given the system emits a Receipt v2 payload as canonical UTF-8 JSON with schema `factory.receipt.v2`
  And the exact payload bytes are bound inside a DSSE envelope with payload type `application/vnd.factory.receipt.v2+json`
  And the system signs the envelope with `Ed25519` and includes a non-empty key id, authenticated identity, and issuer
  And the matching public key in the trust root
  When the system verifies `DSSEv1` pre-authentication encoding, signature, payload digest, trusted key id, authenticated identity, and issuer in `offline` mode
  Then the result is `VERIFIED`
  And the payload digest and signer identity are returned
  And no network call is attempted

Scenario: payload mutation is rejected
  Given a valid Receipt v2 envelope
  When one payload byte changes
  Then verification returns `E_SIGNATURE_INVALID`
  And the result is not `VERIFIED`

Scenario: identity substitution is rejected
  Given a valid envelope signed by identity A
  When the trust root expects identity B for the key id
  Then verification returns `E_IDENTITY_MISMATCH`

Scenario: unknown key is rejected
  Given the system rejects verification with `E_UNKNOWN_KEY` when the key id is unknown or the public key does not match the signature
  When the offline verifier checks the envelope
  Then verification returns `E_UNKNOWN_KEY`

Scenario: policy digest is bound
  Given the system emits a signed policy bundle with schema `factory.policy.bundle.v1`, canonical policy bytes, and a `policy_sha256` digest bound in a DSSE envelope
  And a Receipt v2 envelope declares policy digest P
  And the system requires a verified policy bundle with digest Q
  When Q differs from P
  Then verification returns `E_POLICY_DIGEST_MISMATCH`

Scenario: revoked signer is rejected
  Given the system emits revocation data with schema `factory.revocations.v1` and binds it in a signed DSSE envelope
  And a valid envelope is signed by key id K
  And the verified revocation list revokes K before the receipt timestamp
  When the offline verifier checks the envelope
  Then verification returns `E_SIGNER_REVOKED`

Scenario: invalid signing input is rejected
  Given the system rejects signing with `E_INVALID_RECEIPT` when the payload is not a Receipt v2 object
  When an invalid signing input is submitted
  Then the command returns `E_INVALID_RECEIPT`

Scenario: v1 remains readable but is not enterprise verified
  Given the system returns `LEGACY_UNVERIFIED` when the enterprise verifier receives a readable `factory.receipt.v1` JSON file
  When the enterprise verifier checks it
  Then verification returns `LEGACY_UNVERIFIED`
```

## SHOULD - Technical and structural
- Dependency: Ed25519 support shall be isolated behind the optional
  `enterprise` extra and shall not add network dependencies to verification.
- Determinism: canonical payload and DSSE PAE bytes shall be stable across
  operating systems and JSON key ordering.
- Privacy: verifier output shall include digests and identity metadata, not
  private keys or unnecessary receipt contents.
- Compatibility: the existing `factory receipt sign|verify|status` commands
  shall continue to work for v1 Sigstore sidecars.

## SHOULD NOT - Scope boundaries
- The foundation shall not implement a multi-tenant API, SSO/SCIM, SCM apps,
  hosted evidence store, OSCAL packs, BBS credentials, or zkVM proofs.
- The foundation shall not claim certificate transparency or online revocation
  freshness when operating offline.
- The foundation shall not accept a hash as a substitute for a signature.
- The foundation shall not load private keys from environment variables or
  print private key material.
