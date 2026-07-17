# Spec: capability-packs
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Code Factory shall derive target diversity from signed, mutation-tested
Capability Packs rather than a hard-coded target table. A pack is local data
until its structure, DSSE Ed25519 signature, validator mutations, canaries,
goldens, UX states, and migration policy all verify.

### Requirements (EARS)

- The system shall return marker `PACK_STRUCTURE_VALIDATED` only when every required pack file and field is present and every validator, golden, and canary manifest is non-empty.
- The system shall return marker `PACK_SIGNATURE_VERIFIED` only when the exact current pack file hashes match one trusted offline DSSE Ed25519 envelope.
- If any signed pack file changes, the system shall return marker `PACK_VALIDATION_FAILED` and shall not install the pack.
- The system shall return marker `PACK_VALIDATOR_MUTATIONS_REJECTED` only after rejecting deletion of a required label, replacement of pack kind, removal of all canaries, removal of the accessibility UX state, and removal of deployment profiles.
- The system shall return marker `PACK_DEPLOYMENT_GUIDANCE_COMPLETE` only when every deployment profile stores a unique id, label, prerequisites, build step, verification step, release step, and approval boundary.
- If a pack mutation survives, the system shall return causal code `HOLLOW_PACK_VALIDATOR` and shall not install the pack.
- The system shall return marker `PACK_UX_STATES_COMPLETE` only when its UX-state manifest stores loading, empty, error, success, permission, offline, recovery, and accessibility.
- The system shall return marker `PACK_MIGRATION_POLICY_BOUND` only when the migration policy denies breaking migrations, requires human review, and requires rollback.
- The system shall return marker `PACK_INSTALLED_VERIFIED` only after a verified pack is staged and atomically installed beneath `.factory/packs` with a destination leaf equal to the validated pack `id` field.
- If an installed pack exists, the system shall return causal code `PACK_EXISTS` unless explicit force replacement is requested.
- When force replacement fails after backup, the system shall return marker `PACK_ROLLBACK_RESTORED` after restoring the previous installed pack and before returning the failure.
- The system shall return marker `PACK_PATH_CONTAINED` before writing only when the resolved destination is one direct child of `.factory/packs`.
- The system shall return marker `PACK_INVENTORY_DERIVED` with worker, web, mobile, and agent-ui target metadata derived from first-party signed packs when `factory pack list` runs.
- When target compilation completes, the target compiler shall return marker `TARGET_PACK_BOUND` after storing the selected pack id and version in `target_manifest.json`.
- When target compilation completes, the target compiler shall return marker `TARGET_DEPLOYMENT_PROFILE_BOUND` after storing exactly one pack-owned deployment profile and `external_effects_authorized: false` in `target_manifest.json`.
- The system shall return marker `PACK_SIGNATURE_BYPASS_DENIED` from `factory pack list`, `factory pack validate`, and `factory pack install` because no installation command exposes a signature-bypass mode.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Verify every first-party pack
  Given the installed first-party target packs
  When pack validation runs
  Then every signature is verified
  And all five validator mutations are rejected per pack

Scenario: Reject a tampered pack
  Given one byte in a signed pack changes
  When pack validation runs
  Then validation fails before installation
  And the failure explains the signature or payload mismatch

Scenario: Replace an installed pack safely
  Given a verified pack is already installed
  When an owner requests force replacement
  Then the old directory is backed up before the final rename
  And a failed rename restores the previous directory

Scenario: Reject a pack path escape
  Given a validated pack id containing parent-directory traversal
  When pack installation resolves its destination
  Then marker `PACK_PATH_CONTAINED` is absent
  And no destination is written outside `.factory/packs`

Scenario: Compile through a target pack
  Given a supported target selected from the pack inventory
  When target compilation runs
  Then the target manifest binds the selected pack id and version
  And the target manifest binds one deployment profile with exact build verify release prerequisites and approval guidance
  And external effects are unauthorized
  And deployment publication signing and external messaging remain denied

Scenario: Every requirement has an observable validator marker
  Given the Capability Pack contract
  When strict validator mutation runs
  Then contract markers include `PACK_STRUCTURE_VALIDATED`, `PACK_SIGNATURE_VERIFIED`, `PACK_VALIDATOR_MUTATIONS_REJECTED`, `PACK_DEPLOYMENT_GUIDANCE_COMPLETE`, `PACK_VALIDATION_FAILED`, `HOLLOW_PACK_VALIDATOR`, `PACK_UX_STATES_COMPLETE`, `PACK_MIGRATION_POLICY_BOUND`, `PACK_INSTALLED_VERIFIED`, `PACK_EXISTS`, `PACK_ROLLBACK_RESTORED`, `PACK_PATH_CONTAINED`, `PACK_INVENTORY_DERIVED`, `TARGET_PACK_BOUND`, `TARGET_DEPLOYMENT_PROFILE_BOUND`, and `PACK_SIGNATURE_BYPASS_DENIED`
```

## SHOULD - Technical and structural

- ADR reference: `adr/0010-signed-capability-packs.md`.
- Pack manifests use JSON-compatible YAML 1.2 and canonical SHA-256 file maps.
- Private signing keys never enter the package or repository.
- First-party packs cover headless worker, web application, Expo mobile application, and supervised agent UI targets.

## SHOULD NOT - Implementation details

- Do not execute, deploy, publish, sign releases, grant credentials, call connectors, or send messages during pack validation or installation.
- Do not trust filename presence without verifying file content hashes and signature identity.
- Do not remove a previous install before a staged replacement is ready.
