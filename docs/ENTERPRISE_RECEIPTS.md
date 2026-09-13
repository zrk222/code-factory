# Enterprise Receipt v2 Foundation

FactoryLine 0.10 adds a local trust boundary for enterprise evidence. A v2
receipt is canonical JSON inside a DSSE envelope signed by Ed25519. The
signature metadata binds a key id to an authenticated identity and issuer.

## Quick start

```bash
pip install "factoryline-code-factory[enterprise]"
factory enterprise keygen --out-dir .factory/keys --keyid ci-main \
  --identity "https://github.com/OWNER/REPO/.github/workflows/proof.yml@refs/heads/main" \
  --issuer "https://token.actions.githubusercontent.com"
```

Create a v2 payload with at least `schema`, `module`, `stage`, `feature`, `ok`,
`tenant_id`, `run_id`, and `ts`, then seal it:

```bash
factory enterprise receipt-seal receipt-v2.json \
  --private-key .factory/keys/ci-main.private.pem \
  --keyid ci-main \
  --identity "https://github.com/OWNER/REPO/.github/workflows/proof.yml@refs/heads/main" \
  --issuer "https://token.actions.githubusercontent.com" \
  --out receipt.dsse.json
```

Verify it without network access:

```bash
factory enterprise verify receipt.dsse.json \
  --trust-root .factory/keys/trust-root.json
```

The verifier returns `VERIFIED` only when the exact payload bytes, DSSE PAE,
signature, trusted key, identity, issuer, and receipt schema all pass. It also
returns the tenant id, receipt digest, and whether policy and revocation checks
were performed. By default, a supplied revocation list is a historical check
against the receipt timestamp; it is not a claim that the list is current.

For a release or security review that requires a current offline snapshot, opt
into the strict freshness gate:

```bash
factory enterprise verify receipt.dsse.json \
  --trust-root .factory/keys/trust-root.json \
  --revocations revocations.dsse.json \
  --require-revocations \
  --max-revocation-age 86400
```

Strict mode fails closed when the snapshot is missing, future-dated, older than
the declared bound, or malformed. A passing result reports
`revocation_status: FRESH_CHECKED`, `revocation_freshness: CURRENT`, and the
measured age in seconds. This is an offline evidence freshness fact, not hosted
identity enforcement or proof that an external provider has accepted a
revocation.

## Policy bundles

Sign a JSON policy with the same or a separately trusted key:

```bash
factory enterprise policy-sign factory.policy.json \
  --private-key .factory/keys/ci-main.private.pem \
  --keyid ci-main \
  --identity "https://github.com/OWNER/REPO/.github/workflows/proof.yml@refs/heads/main" \
  --issuer "https://token.actions.githubusercontent.com" \
  --out policy.dsse.json
```

The receipt must carry the SHA-256 digest of the canonical policy JSON in
`policy_sha256`. Verification rejects a bundle with a different digest.

## Revocation

Create a JSON array such as:

```json
[
  {
    "keyid": "old-ci-key",
    "revoked_at": "2026-07-12T00:00:00+00:00",
    "reason": "key rotation"
  }
]
```

Sign it and include it during verification:

```bash
factory enterprise revocations-sign revocations.json \
  --private-key .factory/keys/ci-main.private.pem \
  --keyid ci-main \
  --identity "https://github.com/OWNER/REPO/.github/workflows/proof.yml@refs/heads/main" \
  --issuer "https://token.actions.githubusercontent.com" \
  --out revocations.dsse.json
factory enterprise verify receipt.dsse.json \
  --trust-root .factory/keys/trust-root.json \
  --revocations revocations.dsse.json
```

If the receipt signer is revoked at or before the receipt timestamp, verification
returns `E_SIGNER_REVOKED`. An omitted revocation file is reported as
`NOT_CHECKED`; strict mode instead returns `E_REVOCATION_REQUIRED`. Optional
lists report `CHECKED` with `NOT_ASSERTED` freshness, while strict current lists
report `FRESH_CHECKED`. The verifier never describes either mode as an online
revocation result.

## Fail-closed results

The verifier uses closed codes including `E_SIGNATURE_INVALID`,
`E_UNKNOWN_KEY`, `E_IDENTITY_MISMATCH`, `E_POLICY_DIGEST_MISMATCH`,
`E_SIGNER_REVOKED`, `E_REVOCATION_REQUIRED`, `E_REVOCATION_FRESHNESS`,
`E_INVALID_REVOCATIONS`, and `E_POLICY_REQUIRED`. It never treats a hash as a
signature and never prints private key material.

## Scope

This release delivers the Receipt v2 foundation and a local control-plane
boundary. It does not yet ship a hosted multi-tenant API, SSO/SCIM, SCM apps,
isolated runners, SBOM/VEX, OpenTelemetry connectors, OSCAL packs, BBS
credentials, or zkVM proofs. The local evidence and approval contract is in
[CONTROL_PLANE.md](CONTROL_PLANE.md); the remaining phases are tracked in
[ENTERPRISE_1_0.md](ENTERPRISE_1_0.md).
