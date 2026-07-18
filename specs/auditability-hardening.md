# Spec: auditability-hardening
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Raise the existing Code Factory implementation to an A-grade stranger-audit
standard without inventing enterprise product scope. The lane makes the DSSE
receipt verifier challengeable from the CLI, proves canonical JSON properties,
documents every public Python API, and hardens the least-tested Studio and
migration write/verification paths.

### User roles

- Security reviewer independently challenging the offline receipt chain.
- Contributor auditing a public API without reconstructing behavior from its body.
- Maintainer testing Studio decision writes and migration evidence against hostile inputs.

### Requirements (EARS)

- The system shall emit `VERIFY_RECEIPTS_COMMAND_AVAILABLE` only when a `verify-receipts` command exposes an offline mutation gate that creates ephemeral Ed25519 material, verifies one valid DSSE Receipt v2 control, requires `E_PAYLOAD_DIGEST_MISMATCH` for a one-byte payload mutation, `E_SIGNATURE_INVALID` for a rebound digest without a replacement signature, `E_IDENTITY_MISMATCH` for an identity swap, and `E_SIGNER_REVOKED` for a revocation dated before the receipt, and emits `RECEIPT_MUTATIONS_REJECTED` only when every mutation returns its expected code. [REQ-AUD-RECEIPTS]
- The system shall write a canonical mutation-gate receipt to the declared challenge evidence location, record attempted and rejected counts, expected and observed error codes, bind the control receipt digest, emit `RECEIPT_MUTATION_CODE_MISMATCH` when a rejection reason differs, emit `RECEIPT_MUTATION_SURVIVED` when a mutation verifies, and return a non-zero command exit for either failure. [REQ-AUD-MUTATION-RECEIPT]
- The system shall emit `RECEIPT_CHALLENGE_OFFLINE` only when the receipt challenge performs no network access, preserves no private key outside its temporary directory, grants no signing, merge, publication, deployment, connector, credential, or external-message authority, and converts unexpected verifier failures into a failed mutation result rather than a false pass. [REQ-AUD-OFFLINE]
- When canonicalization receives a JSON-safe value composed of null, booleans, bounded integers, finite floats, Unicode strings without lone surrogates, lists, and string-keyed dictionaries, the system shall emit `CANONICAL_ROUNDTRIP_STABLE` only when JSON parsing and canonicalization produce byte-identical output and dictionary insertion order does not affect output. [REQ-AUD-CANONICAL]
- When canonicalization receives NaN, positive or negative infinity, a lone surrogate, or a non-JSON object, the system shall fail closed with `E_INVALID_PAYLOAD` rather than leaking an unclassified encoding exception. [REQ-AUD-CANONICAL-INVALID]
- The system shall emit `PUBLIC_API_DOCSTRINGS_COMPLETE` only when every distributed public package function and callable member has a meaningful docstring of at least twenty non-whitespace characters that describes behavior and public fail-closed receipt, Studio, migration, control-plane, signing, and policy surfaces identify their domain error type or principal refusal semantics. [REQ-AUD-DOCSTRINGS]
- The system shall reject Studio mission-decision requests with `TOKEN_REQUIRED` for a wrong token, `PATH_REJECTED` for a mission outside the Studio root, and the existing `ARTIFACT_EXISTS` domain code for a replay that would replace an existing decision receipt; every rejection shall leave the first decision receipt unchanged. [REQ-AUD-STUDIO]
- The system shall emit `MIGRATION_ASSESSMENT_FAILS_CLOSED` only when invalid migration command declarations and evidence outside the repository root return the existing domain error codes, insufficient environment reproducibility remains unready, and implicit receipt replacement is refused without explicit replacement authority. [REQ-AUD-MIGRATION-ASSESS]
- When migration evidence contains `MIGRATION_EVIDENCE_ROW_MALFORMED`, missing files, digest drift, or malformed stored hashes, the system shall return a structured invalid verdict instead of raising an unclassified exception. [REQ-AUD-MIGRATION-VERIFY]
- The system shall emit `SIGSTORE_WORKFLOW_SINGLE` only when the existing Sigstore identity workflow remains the single networked Sigstore CI path with the optional Sigstore installation, GitHub OIDC, and exact workflow identity and issuer checks. [REQ-AUD-SIGSTORE]
- The system shall emit `AUDITABILITY_SCOPE_BOUNDED` only when the lane does not split the command dispatcher, add SSO/SCIM, create a hosted control plane, add HA claims, or manufacture procurement/compliance artifacts without design-partner demand. [REQ-AUD-SCOPE]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Challenge the offline signing chain
  Given no persistent signing key and no network service
  When the maintainer runs the verify-receipts command
  Then VERIFY_RECEIPTS_COMMAND_AVAILABLE is emitted
  And one valid control receipt verifies offline
  And the one-byte payload mutation returns E_PAYLOAD_DIGEST_MISMATCH
  And the rebound digest without a replacement signature returns E_SIGNATURE_INVALID
  And the identity swap returns E_IDENTITY_MISMATCH
  And the back-dated revocation returns E_SIGNER_REVOKED
  And four receipt mutations are rejected for their expected error codes
  And the marker is RECEIPT_MUTATIONS_REJECTED
  And the challenge preserves no private key and performs no network access
  And the receipt grants no external-effect authority

Scenario: Prove canonical JSON stability
  Given bounded integers, finite floats, Unicode without lone surrogates, lists, dictionaries, booleans, and null
  When canonical bytes are parsed and canonicalized again
  Then the bytes are identical
  And dictionary insertion order does not change the bytes
  And non-finite floats, lone surrogates, and non-JSON objects return E_INVALID_PAYLOAD

Scenario: Make every public API auditable
  Given the distributed public package functions and callable members
  When the documentation contract scans public functions and methods
  Then none are missing a docstring of at least twenty non-whitespace characters
  And fail-closed public surfaces name their refusal semantics

Scenario: Reject hostile Studio decision writes
  Given one contained product mission and an existing decision receipt
  When a wrong token, mission path outside the Studio root, or decision replay is supplied
  Then the response is TOKEN_REQUIRED, PATH_REJECTED, or ARTIFACT_EXISTS respectively
  And the first decision receipt remains byte-identical

Scenario: Reject hostile migration evidence
  Given one valid migration receipt and one repository-context receipt
  When a command is not a non-empty argument vector or evidence is outside the repository root
  Then the assessor returns its existing migration domain error
  And insufficient environment reproducibility stays unready
  And implicit receipt replacement is refused
  And MIGRATION_EVIDENCE_ROW_MALFORMED returns a structured invalid verdict
  And missing files, digest drift, and malformed stored hashes return structured invalid verdicts
  And no unclassified exception escapes

Scenario: Preserve the existing Sigstore path and product boundary
  Given the identity-pinned GitHub OIDC Sigstore workflow
  When the hardening lane is reviewed
  Then exactly one networked Sigstore workflow remains
  And the optional Sigstore installation, exact identity, and issuer checks remain
  And the command dispatcher is not split
  And no SSO, SCIM, hosted control plane, HA, procurement, or compliance feature is added
```

## SHOULD - Technical and structural

- Put the runnable challenge in `factoryline/receipt_challenge.py`; keep the core verifier independent from CLI orchestration.
- Expose the exact interface as `factory verify-receipts --root . --out receipt.json --json` and default the receipt to `.factory/challenges/verify-receipts.json`.
- Use Hypothesis only in the development/test extra; runtime installation remains unchanged.
- Keep the existing protected PyPI and Sigstore workflows unchanged except for deterministic contract assertions if needed.
- Keep the CLI split as a separately planned refactor after this lane.

## SHOULD NOT - Implementation details

- Do not call Sigstore, GitHub, PyPI, Zenodo, Product Hunt, or another network service from the receipt mutation gate.
- Do not preserve ephemeral private keys in a challenge receipt.
- Do not weaken existing error-code specificity to make tests easier.
- Do not add speculative enterprise identity, hosting, scale, or compliance features.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `RECEIPT_MUTATION_CODE_MISMATCH` | fail the gate and record both codes |
| 2 | `RECEIPT_MUTATION_SURVIVED` | fail the gate and exit non-zero |
| 3 | canonical input cannot be encoded as supported JSON | raise `E_INVALID_PAYLOAD` |
| 4 | `ARTIFACT_EXISTS` | refuse the Studio decision replay and preserve the first receipt |
| 5 | `MIGRATION_EVIDENCE_ROW_MALFORMED` | return structured invalid verification |
| 6 | `RECEIPT_MUTATIONS_REJECTED` | pass only when every declared receipt mutation returns its exact expected code |
| 7 | `RECEIPT_CHALLENGE_OFFLINE` | persist no private key and grant no external-effect authority |
| 8 | `CANONICAL_ROUNDTRIP_STABLE` | accept the bounded canonicalization property |
| 9 | `PUBLIC_API_DOCSTRINGS_COMPLETE` | accept the public documentation contract |
| 10 | `MIGRATION_ASSESSMENT_FAILS_CLOSED` | accept the migration assessment contract |
| 11 | `SIGSTORE_WORKFLOW_SINGLE` | preserve one identity-pinned Sigstore workflow |
| 12 | `AUDITABILITY_SCOPE_BOUNDED` | reject speculative enterprise and CLI-split scope |
| 13 | `VERIFY_RECEIPTS_COMMAND_AVAILABLE` | expose the offline receipt mutation gate |

## Claim and evidence boundary

- This lane proves local verifier behavior, not arbitrary production security.
- A docstring contract improves auditability; it does not replace code review.
- Existing Sigstore CI is verified as present and identity-pinned; no new network trust claim is introduced.
- `cli.py` modularization and speculative enterprise features are explicit non-goals.
