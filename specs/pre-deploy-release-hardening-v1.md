# Spec: pre-deploy-release-hardening-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Provide one fail-closed, read-only pre-deploy gate for the Code Factory release
owner. The gate binds the exact source version and commit to the approved
release contract, rejects stale or mixed-version artifacts, classifies Codex
metadata as active or archival with ledger/state evidence, and closes the
Windows process-tree assignment race before a worker is resumed. It never
publishes, deploys, signs, accesses credentials, or changes a candidate tree.

### User roles
- Release owner: supplies the approved Oracle contract and reviews the receipt.
- Independent verifier: runs the deterministic checks and may not edit the contract.
- Worker agent: may produce code/artifacts but cannot change the sealed contract.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- The system shall return `RELEASE_CONTRACT_SOURCE_MISMATCH` and reject a release candidate unless its contract schema, feature, Oracle digest, approved stage set, source version, and source commit all match the inspected workspace.
- When a candidate directory contains an artifact, the system shall return `E_RELEASE_ARTIFACT_VERSION_MISMATCH` after parsing its version from the filename when that version differs from the source-declared version for that package family; a missing or unreadable inventory is also blocking.
- The system shall attach an explicit scope equal to `active` or `archive` to every metadata finding, and shall exclude every archival terminal claim from active release evidence.
- When `E_METADATA_LEDGER_ORDER` evaluates `context/PROGRESS.md` containing a non-monotonic timestamp or a `head=` value different from the current commit in active scope, the system shall return `E_METADATA_LEDGER_ORDER` or `E_METADATA_LEDGER_HEAD_MISMATCH` with the line location.
- If a `.forge` state record has no matching receipt lineage, the system shall return `E_METADATA_STATE_RECEIPT_MISMATCH` instead of treating the state as proof.
- When `E_WINDOWS_BINDING_REQUIRED` runs on Windows, the command launcher shall return `E_WINDOWS_BINDING_REQUIRED` after creating the cleanup Job Object before resuming the suspended child; if job setup or resume fails, it shall terminate the child and return a non-success launch result; a successful resume shall call `NtResumeProcess` after assignment.
- The system shall return `RELEASE_CANDIDATE_PREFLIGHT_PASS` through a machine-readable receipt with stable schema, check IDs, evidence, and explicit authority flags set to false when all four checks pass.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: exact candidate contract is required
  Given a workspace whose release contract is missing, malformed, or bound to another commit
  When the release preflight is evaluated
  Then the result is not ready and includes RELEASE_CONTRACT_SOURCE_MISMATCH

Scenario: stale artifact is rejected
  Given source version 0.46.3 and a candidate directory containing factoryline_code_factory-0.46.2-py3-none-any.whl
  When candidate preflight is evaluated
  Then the result contains E_RELEASE_ARTIFACT_VERSION_MISMATCH and is not ready

Scenario: metadata scope is explicit
  Given an active or archival metadata record
  When the metadata audit emits a finding
  Then the finding contains an explicit scope value of `active` or `archive`

Scenario: active ledger drift is rejected
  Given E_METADATA_LEDGER_ORDER identifies an active progress ledger with an out-of-order timestamp or stale head SHA
  When metadata audit evaluates the ledger
  Then the result contains E_METADATA_LEDGER_ORDER

Scenario: active ledger drift is visible but archival history is bounded
  Given an active progress ledger with an out-of-order timestamp and a stale head SHA, plus archival terminal records
  When metadata audit runs with scope active
  Then it reports E_METADATA_LEDGER_ORDER and E_METADATA_LEDGER_HEAD_MISMATCH with line locations
  And archival records are excluded from active release evidence

Scenario: state requires receipt lineage
  Given E_METADATA_STATE_RECEIPT_MISMATCH identifies a terminal `.forge` state record with no matching feature and receipt digest
  When metadata audit runs
  Then it reports E_METADATA_STATE_RECEIPT_MISMATCH

Scenario: Windows cleanup binding precedes execution
  Given E_WINDOWS_BINDING_REQUIRED is evaluated by a Windows launcher that creates a suspended child
  When Job Object assignment succeeds
  Then E_WINDOWS_BINDING_REQUIRED is returned and NtResumeProcess is called only after assignment
  And a setup or resume failure returns cleanup_confirmed=false

Scenario: preflight receipt remains read-only
  Given every local hardening fact is true
  When the candidate preflight is evaluated
  Then the marker is RELEASE_CANDIDATE_PREFLIGHT_PASS
```

## SHOULD — Technical/structural
- ADR references: existing Oracle Firewall and release-contract verifier remain
  the single policy source; this feature adds only an evidence projection.
- Data model: `factory.release-candidate-preflight.v1` and `factory.codex-metadata-integrity.v1` receipts with `schema_version: 2` metadata and SHA-256 hashes (`contract_valid`, `artifact_versions_match`, `metadata_lineage_valid`, `ledger_drift`, `windows_binding_proven`).
- API contract: `release_candidate_preflight(root, contract, artifact_dirs)`
  and `audit_metadata(root, paths=None, scope="active")` are pure functions;
  CLI `factory release preflight` and `factory ops metadata --scope` are
  read-only.

## SHOULD NOT — Implementation details
<!-- Leave the "how" to the plan/tasks unless it is a systemic invariant -->

## Decision logic (factory candidates)
<!-- Ordered business rules over extracted facts. specline handoff compiles
     these via HSF instead of letting agents improvise them. -->
| # | if | then |
|---|----|------|
| 1 | `contract_valid=false` | block with `RELEASE_CONTRACT_INVALID` |
| 2 | `artifact_versions_match=false` | block with `E_RELEASE_ARTIFACT_VERSION_MISMATCH` |
| 3 | `metadata_lineage_valid=false` or `ledger_drift=true` | block with the deterministic metadata finding |
| 4 | `windows_binding_proven=false` | terminate, return non-success, and never claim cleanup |
| 5 | `contract_valid=true`, `artifact_versions_match=true`, `metadata_lineage_valid=true`, `ledger_drift=false`, and `windows_binding_proven=true` | return `RELEASE_CANDIDATE_PREFLIGHT_PASS`; external publication remains out of scope |
