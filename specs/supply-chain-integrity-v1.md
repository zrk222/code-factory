# Spec: supply-chain-integrity-v1
Status: implemented

## Declared facts

- `source_bound`: source descriptors are current, sorted, and equal to the
  candidate digest.
- `dependency_bound`: lockfile, SBOM, VEX, and licence-policy descriptors are
  current and hash-bound.
- `blocked`: a deterministic check returned a stable blocker and no PASS.
- `verified`: an external DSSE signature and every referenced file check pass;
  this is evidence verification, not release approval.
- `reproducible`: two to four clean rebuilds have identical artifact path and
  digest sets.
- `secret_free`: package bytes and archive members contain no secret-shaped
  material or unsafe path.

## Declared outputs

The closed blocker set includes `E_LICENSE_POLICY`,
`E_COLLECTOR_INDEPENDENCE`, `E_REPRO_BUILD_DRIFT`, and
`E_SECRET_IN_ARTIFACT`.

## MUST

### Requirements (EARS)

- The system shall emit `SOURCE_MANIFEST_BOUND` after binding a canonical source manifest and at least one lockfile to the candidate digest, and shall reject paths outside the workspace and symlinks. [R10]
- When SBOM and VEX files are evaluated, the system shall emit `SBOM_BOUND` and `VEX_POLICY_BOUND` only after requiring Factory schemas, embedded digests, unresolved-entry severity, and policy thresholds. [R20]
- If a licence is denied or unknown, the system shall emit `LICENSE_POLICY_BOUND` only after requiring a current named exception with reason and expiry no more than 24 hours ahead, and shall return `BLOCKED` when the exception is absent or expired. [R30]
- When a reproducible build is evaluated, the system shall emit `REPRODUCIBLE_BUILDS` only after requiring two to four clean rebuilds with identical artifact path and digest sets, and shall return `BLOCKED` with `E_REPRO_BUILD_DRIFT` when the sets differ. [R40]
- When a PASS is emitted, the system shall emit `ARTIFACT_SECRET_SCAN` only after inspecting release artifact bytes for secret-shaped material and unsafe archive paths, and shall return `BLOCKED` with `E_SECRET_IN_ARTIFACT` on a finding. [R50]
- When a signed attestation is verified, the system shall emit `INDEPENDENT_ATTESTATION_VERIFIED` only after requiring an independent collector and preserving `authority: none` and `release_approval: false`. [R60]
- The system shall emit `RECEIPT_SELF_HASHED` for a self-hashed read-only receipt and shall never imply provider, marketplace, merge, signing, deployment, or approval authority. [R70]

## Declared bounds

The validator accepts at most 2048 descriptors, 4096 components or entries, and
16 MiB (16 x 1024 x 1024 bytes) of archive contents. Descriptor byte counts
have a minimum of 0; JSON is decoded as UTF-8; timestamps allow the RFC3339
`Z` marker and `+00:00` offset; strings are capped at 64 characters for
timestamps and 1024 characters for exception reasons. Each descriptor list
requires at least 1 item, each rebuild contains at least 1 artifact, and 2 to
4 rebuilds are required. Threshold counts range from 0 to 4096 and the
attestation window is at most 86400 seconds (24 hours).

## Acceptance

```gherkin
Scenario: a changed build is blocked
  Given two rebuilds with different artifact digests
  When the supply-chain evaluator runs
  Then it returns BLOCKED with E_REPRO_BUILD_DRIFT

Scenario: a release artifact contains a secret
  Given a package containing a private-key or provider-token pattern
  When the artifact scan runs
  Then it returns BLOCKED with E_SECRET_IN_ARTIFACT

Scenario: an external signature verifies evidence only
  Given a DSSE attestation signed by an independent collector
  When it is checked against the local trust root
  Then state is VERIFIED and release_approval remains false

Scenario: source and dependency binding is observable
  Given requirement R10 receives a source manifest and lockfile
  When the evaluator checks the candidate
  Then the evaluator emits SOURCE_MANIFEST_BOUND or returns BLOCKED

Scenario: software inventory policy is observable
  Given requirement R20 receives SBOM and VEX files
  When the evaluator checks their embedded digests and thresholds
  Then the evaluator emits SBOM_BOUND and VEX_POLICY_BOUND or returns BLOCKED

Scenario: licence exceptions are observable
  Given requirement R30 receives a denied licence without a current exception
  When the evaluator checks the policy
  Then the evaluator emits LICENSE_POLICY_BOUND or returns BLOCKED with E_LICENSE_POLICY

Scenario: rebuild identity is observable
  Given requirement R40 receives two rebuilds with different artifact digests
  When the evaluator compares the rebuilds
  Then the evaluator emits REPRODUCIBLE_BUILDS or returns BLOCKED with E_REPRO_BUILD_DRIFT

Scenario: artifact scanning is observable
  Given requirement R50 receives an archive containing a provider token
  When the evaluator scans release artifacts
  Then the evaluator emits ARTIFACT_SECRET_SCAN or returns BLOCKED with E_SECRET_IN_ARTIFACT

Scenario: collector independence is observable
  Given requirement R60 receives a signed attestation from a local collector
  When the evaluator verifies the signature
  Then the evaluator emits INDEPENDENT_ATTESTATION_VERIFIED or returns BLOCKED with E_COLLECTOR_INDEPENDENCE

Scenario: receipt authority is observable
  Given requirement R70 receives a valid evidence result
  When the evaluator writes the receipt
  Then the evaluator emits RECEIPT_SELF_HASHED with release_approval false
```
