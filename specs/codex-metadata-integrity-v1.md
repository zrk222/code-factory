# Spec: codex-metadata-integrity-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST — Functional core
### Description
Audit explicitly selected local Codex/workflow metadata before it can be used as
evidence for a terminal engineering, release, or provider claim. The auditor is
deterministic, read-only, offline, and authority-free. It binds every inspected
file by SHA-256 and reports malformed, stale, contradictory, or unbound claims
instead of silently accepting them.

### Declared facts

- `metadata_path_contained`: every selected file resolves inside the selected
  workspace and no symlink/path escape is accepted.
- `metadata_parseable`: JSON and JSONL inputs parse completely; unsupported
  formats and malformed records remain visible as review findings.
- `terminal_claim_bound`: a terminal claim has structured evidence with a
  command, artifact/path, provider read-back, or hash anchor.
- `status_coherent`: a record does not claim success while also declaring a
  pending, blocked, partial, or failed state.
- `active_execution_bound`: an active state has execution identity or bounded
  evidence; an orphan `active` state is not treated as running.
- `workspace_identity_consistent`: explicit workspace/cwd paths resolve to the
  selected workspace.

### Requirements (EARS)

- The system shall inspect only explicitly selected workspace-contained files (or the documented default metadata inventory), hash every file, and emit `CODEX_METADATA_INPUT_ACCEPTED` and `CODEX_METADATA_HASHED`; inventories shall be limited to 256 files and 1048576 bytes per file, and path escapes, missing inputs, and symlink escapes shall fail closed before a verified result. [REQ-META-INPUT]
- When JSON or JSONL metadata is read, the system shall parse every record and report malformed or unsupported input as `E_METADATA_PARSE_INVALID` with its path and record/line location; the system shall never skip an unreadable record. [REQ-META-PARSE]
- If a metadata record claims a terminal state, the system shall include `E_METADATA_UNBOUND_TERMINAL` when the record lacks a structured evidence anchor (command, artifact/path, provider read-back URL, or SHA-256); terminal values include success, complete, published, verified, and ready. [REQ-META-BOUNDARY]
- If a terminal claim has only a command or path but no receipt, SHA-256, verified timestamp, artifact digest, or read-back URL, the system shall emit `E_METADATA_WEAK_EVIDENCE` and keep status `REVIEW_REQUIRED`. [REQ-META-STRENGTH]
- If a record combines a terminal claim with pending, blocked, partial, failed, or unknown state, the system shall emit `E_METADATA_CONTRADICTORY_STATUS`; if provider completion lacks a provider receipt/read-back URL, the system shall emit `E_METADATA_PROVIDER_UNBOUND`. [REQ-META-COHERENCE]
- If a record reports active without execution identity or evidence, the system shall emit `E_METADATA_ORPHAN_ACTIVE`; if explicit workspace/cwd paths resolve outside the selected workspace, the system shall emit `E_METADATA_WORKSPACE_MISMATCH`. [REQ-META-IDENTITY]
- If a record claims that tests, gates, or an autonomous review passed but identifies only the coding agent (or no independent verifier), the system shall emit `E_METADATA_SELF_ATTESTED_GATE`; a gate shall not count as evidence because the coding agent marked it green. [REQ-META-INDEPENDENCE]
- If a test or gate pass claim lacks negative/adversarial evidence such as mutation, an empty implementation, a holdout, a counterexample, or an explicit challenge, the system shall emit `E_METADATA_GATE_NO_NEGATIVE_PROOF`. [REQ-META-NEGATIVE]
- If a terminal or gate claim has no bound, clear intent (intent_id, a 64-character intent_hash, or a confirmed intent record), the system shall emit `E_METADATA_INTENT_UNBOUND`; if intent is ambiguous, unclear, or `needs_clarification`, the system shall emit `E_METADATA_INTENT_UNCLEAR`. [REQ-META-INTENT]
- The system shall emit `CODEX_METADATA_CLAIMS_CHECKED` and status `VERIFIED` for a clean audit; any finding shall emit `CODEX_METADATA_REVIEW_REQUIRED` and status `REVIEW_REQUIRED`; the result shall set execute, merge, deploy, release, publish, and billing authority to false. [REQ-META-RESULT]
- When `CODEX_METADATA_CLI_WRITTEN` is emitted by `factory ops metadata`, the system shall write the output atomically beneath the workspace and return exit code 0 only for `VERIFIED`; `REVIEW_REQUIRED` shall return exit code 1. [REQ-META-CLI]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Bound terminal records verify
  Given JSON and JSONL records with a complete status and a command plus SHA-256
  When the metadata audit runs
  Then every file is hashed and the status is VERIFIED
  And all authority fields are false

Scenario: A success claim without evidence cannot pass
  Given a record with status published and no receipt, artifact, command, URL, or hash
  When the metadata audit runs
  Then status is REVIEW_REQUIRED
  And E_METADATA_UNBOUND_TERMINAL identifies the record

Scenario: Provider and pending claims remain visible
  Given a record claiming a provider publication while also saying pending
  When the metadata audit runs
  Then E_METADATA_CONTRADICTORY_STATUS and E_METADATA_PROVIDER_UNBOUND are present

Scenario: Malformed input is not skipped
  Given a JSONL file with one valid line and one malformed line
  When the metadata audit runs
  Then the malformed line is named in review_required
  And the audit is not VERIFIED

Scenario: Orphan execution state cannot imply progress
  Given a record with status active and no run identity or evidence
  When the metadata audit runs
  Then E_METADATA_ORPHAN_ACTIVE is present

Scenario: A coding agent cannot grade its own gate
  Given a record with tests_passed true, an author_agent, and no independent verifier
  When the metadata audit runs
  Then E_METADATA_SELF_ATTESTED_GATE is present

Scenario: A green test needs a negative proof
  Given a record with tests_passed true and an independent verifier but no mutation or holdout evidence
  When the metadata audit runs
  Then E_METADATA_GATE_NO_NEGATIVE_PROOF is present

Scenario: A gate cannot pass against an unclear intent
  Given a record with tests_passed true and intent_status "needs_clarification"
  When the metadata audit runs
  Then E_METADATA_INTENT_UNCLEAR is present

Scenario: Every integrity obligation has an observable marker
  Given a metadata audit is evaluated
  When each obligation is checked
  Then CODEX_METADATA_INPUT_ACCEPTED, E_METADATA_PARSE_INVALID, E_METADATA_UNBOUND_TERMINAL, E_METADATA_WEAK_EVIDENCE, E_METADATA_CONTRADICTORY_STATUS, E_METADATA_PROVIDER_UNBOUND, E_METADATA_ORPHAN_ACTIVE, E_METADATA_WORKSPACE_MISMATCH, E_METADATA_SELF_ATTESTED_GATE, E_METADATA_GATE_NO_NEGATIVE_PROOF, E_METADATA_INTENT_UNBOUND, CODEX_METADATA_CLAIMS_CHECKED, CODEX_METADATA_REVIEW_REQUIRED, and CODEX_METADATA_CLI_WRITTEN remain traceable

Scenario: CLI read-back is bounded
  Given a selected metadata directory and an output path beneath the workspace
  When factory ops metadata writes the audit
  Then the JSON output contains its file hashes and marker CODEX_METADATA_CLI_WRITTEN
  And a review-required result exits 1
```

## SHOULD — Technical/structural

- API contract: `factoryline.codex_metadata.audit_metadata` and
  `write_metadata_audit`; CLI under `factory ops metadata`.
- The auditor performs no model call, network request, subprocess, mutation,
  provider lookup, or publication.
- Findings are sorted by path, record location, and code; output hashes exclude
  the output path and dynamic timestamps.

## SHOULD NOT — Implementation details

- Do not infer publication, approval, unique users, or production readiness
  from a claim that lacks provider read-back evidence.
- Do not convert malformed or unsupported input into an empty inventory.
