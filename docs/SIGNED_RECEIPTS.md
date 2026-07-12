# Signed Factory Receipts

A factory receipt records what a gate observed. A Sigstore bundle adds the
missing issuer claim: which OIDC identity signed those exact receipt bytes, with
certificate and transparency-log verification material in one sidecar file.

## Install

```bash
pip install "factoryline-code-factory[sigstore]"
```

## Sign

```bash
factory receipt sign .factory/receipts/factoryline-checkout-verify-abc123.json
```

Local signing opens Sigstore's OIDC authentication flow. In supported CI
systems, Sigstore uses the ambient workload identity instead. Successful
signing writes the standard sidecar:

```text
.factory/receipts/factoryline-checkout-verify-abc123.json.sigstore.json
```

The bundle includes the signature, short-lived certificate, and transparency
verification material. Code Factory does not copy the receipt body into its
command result.

## Verify The Expected Signer

Never infer the signer from the receipt or accept any valid Sigstore identity.
Specify the identity and issuer your policy expects:

```bash
factory receipt verify .factory/receipts/factoryline-checkout-verify-abc123.json \
  --cert-identity "https://github.com/OWNER/REPO/.github/workflows/WORKFLOW.yml@refs/heads/main" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com"
```

Success returns JSON with:

```json
{
  "schema": "factory.sigstore.result.v1",
  "verification_method": "sigstore_identity",
  "verdict": "SIGSTORE_IDENTITY_VERIFIED"
}
```

Changing the receipt, bundle, expected identity, or expected issuer makes the
command exit non-zero with `E_VERIFICATION_FAILED`. A receipt without a sidecar
returns `UNSIGNED`; Code Factory never upgrades that state to `VERIFIED`.

## GitHub Actions

The repository workflow
[`signed-receipts.yml`](../.github/workflows/signed-receipts.yml) creates a real
receipt, signs it with GitHub's ambient OIDC identity, verifies that exact
workflow identity, and uploads both files as one artifact. It requires only:

```yaml
permissions:
  contents: read
  id-token: write
```

No signing key or API secret is stored in the repository.

## Scope

This release authenticates existing receipts. It does not yet implement the
multi-tenant control plane, signed policy bundles, revocation, OSCAL, BBS, or
zkVM architecture described in `ENTERPRISE_1_0.md`. Those remain a vision until
external usage provides a concrete requirement.
