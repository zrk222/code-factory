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

- The system shall verify `REQ_EXECUTION_INVENTORY` by inventorying up to 50000 Git-tracked and nonignored untracked paths with a 16777216-byte file bound and 1073741824-byte total snapshot bound; it shall reject links, unreadable inputs, case collisions, nested repositories and truncation as INCOMPLETE, include dirty source digests, and never count an unknown source type as analyzed.
- The system shall verify `REQ_EXECUTION_BOUNDARY` by requiring a manifest SHA-256 pin, Docker images pinned by SHA-256, nonroot workers, read-only candidate mounts, no network, no added capabilities, 64 through 32768 MiB memory, 128 child PIDs, and 1 through 3600 seconds per lane, and no host execution fallback; it shall preserve every missing prerequisite as INCOMPLETE and never gain release authority.
- The system shall verify `REQ_EXECUTION_EVIDENCE` by persisting sequenced events, exact report bindings, per-file coverage, seeded positive and negative challenges, actionable finding records and interrupted-run state; it shall reject changed source, malformed reports, silent engine downgrades and stale reuse, and require independent signed reviewer evidence before READY_FOR_HUMAN_REVIEW.

## SHOULD NOT - Non-goals

- The existing verification APIs perform no analyzer execution, network lookup, key discovery, patch application,
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


## Executable audit extension

Status: approved by the repository owner request to complete the deep-audit plan.
The existing evaluate, compare and attestation entry points retain their read-only contracts. Execution requires the new explicit scan command and an operator-supplied SHA-256 pin of the execution manifest.

### Declared facts

- `INCOMPLETE` means required evidence or execution coverage is missing.
- `READY_FOR_HUMAN_REVIEW` means the scoped execution and independently signed review evidence satisfy the pinned policy; authority stays none.

### Requirements (EARS)


```gherkin
Scenario: Account for complete candidate source
  Given REQ_EXECUTION_INVENTORY covers tracked and nonignored untracked inputs
  When a tracked source is deleted or linked outside the repository
  Then inventory is INCOMPLETE and the missing path remains visible

Scenario: Preserve isolation prerequisites
  Given REQ_EXECUTION_BOUNDARY requires a pinned image and no network
  When a scanner image is absent or Docker is unavailable
  Then the lane is INCOMPLETE and no host command fallback executes

Scenario: Preserve actionable evidence and review separation
  Given REQ_EXECUTION_EVIDENCE binds all required reports to a candidate
  When review provenance is missing or a report is modified
  Then the run cannot become READY_FOR_HUMAN_REVIEW
```
