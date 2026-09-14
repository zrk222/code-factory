# Supply-chain assurance

FactoryLine now offers an optional, fail-closed release gate that binds a
candidate to its source snapshot, lockfiles, CycloneDX SBOM, VEX decisions,
licence policy, repeated build outputs, and artifact secret scan.

```text
source snapshot -> lockfiles/SBOM/VEX/licence policy -> two identical builds
               -> archive/secret scan -> hash-bound receipt -> human review
```

Run it locally with:

```text
factory assurance supply-chain manifest.json --root . --out .factory/supply-chain/supply-chain-receipt.json --json
```

To make the release candidate preflight include this gate, add
`--supply-chain-manifest path/to/manifest.json` to `factory release preflight`.
An invalid descriptor, changed artifact, unresolved vulnerability over policy,
unapproved licence, unsafe archive member, secret-shaped material, or
non-reproducible rebuild returns a stable blocker such as
`E_REPRO_BUILD_DRIFT` or `E_SECRET_IN_ARTIFACT`.

An independent collector can produce the same attestation as a DSSE Ed25519
document and be checked with `factory assurance supply-chain-verify`. The
verifier requires a non-local collector. A signature proves the supplied
evidence and identity only; it never approves, signs, publishes, deploys, or
merges a release. Marketplace, CI, platform, and human approval remain
separate gates.

Mission Control and Graph Ops read the local receipt without executing it and
surface `PASS`, `BLOCKED`, `INCOMPLETE`, or `MISSING`. The local receipt is not
a claim of external security certification or reproducibility beyond the
files and builds it names.
