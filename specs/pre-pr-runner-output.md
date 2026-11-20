# Spec: pre-pr-runner-output
Status: human architecture approved 2026-11-19; implementation verification in progress
Approval-boundary: owner said "Approve architecture; implement and test"; no merge or release approval inferred

## MUST - Functional core
### Description
Capture declared reports from the actual copied check workspace for local proof reuse.
### User roles
- Local pre-PR caller declares report paths; human retains release authority.
### Requirements (EARS)
- The system shall return `E_REPLAY_OUTPUT` for invalid capture_outputs; valid declarations contain 1 through 16 unique .factory/reports/ regular files, matching existing MAX_NATIVE_ARTIFACTS=16, and aggregate captured bytes at most the declared max_output_bytes, whose existing range is 1 through 1048576 bytes.
- When an executed check exits zero with cleanup confirmed, the system shall enforce `capture_before_cleanup` by emitting `captured_outputs` before temporary workspace deletion.
- If any output ownership overlaps another gate, the system shall enforce `output_overlap_rejection` by returning `E_PRE_PR_OUTPUT` before dispatch; missing, linked, escaping or changed reports reject proof admission.
- The system shall reject proof admission when input, config, environment or executable identity changes and retain the existing `source_stable` boundary.
- When identical inputs and captured reports recur, the system shall return `VERIFIED_REUSE` with zero duplicate check subprocesses.
- The system shall reject `protected_output_paths` overlap when capture paths intersect any declared input or dependency closure, source/configuration binding, oracle artifact, intent artifact, authority artifact, manifest or contract binding before dispatch, including bindings located under .factory/reports/; no protected file may be overwritten by host report export.
- The system shall enforce `export_admission` by exporting only an actual successful executed check with confirmed cleanup; planned, failed, cancelled or cleanup-unconfirmed checks shall never export a report or seed reusable proof.
- The system shall emit `actual_cli_controls` evidence through the existing CLI and real check subprocesses for first absent output, rewritten output, exact second-run reuse with zero duplicate subprocesses, tamper, missing/linked/escaping output, ownership/protected-binding overlap, 16-file and 1048576-byte boundaries, failed/planned/cancelled execution and cleanup failure.
### Acceptance criteria (Gherkin)
```gherkin
Scenario: First generated report
  Given an absent declared .factory/reports/check.json report
  When an executed check exits zero with cleanup confirmed
  Then a second invocation launches zero duplicate check subprocesses
Scenario: Unsafe generated report
  Given a missing or linked declared report
  When an executed check exits zero with cleanup confirmed
  Then proof admission is refused
Scenario: Declared outcomes remain traceable
  Given an `E_REPLAY_OUTPUT` outcome
  And a `captured_outputs` outcome
  And an `E_PRE_PR_OUTPUT` outcome
  And a `source_stable` outcome
  And a `VERIFIED_REUSE` outcome
  And a `protected_output_paths` outcome
  And an `export_admission` outcome
  And an `actual_cli_controls` outcome
  And a `capture_before_cleanup` outcome
  And an `output_overlap_rejection` outcome
  When the contract validates these outcomes
  Then every outcome is declared by a requirement
```
## SHOULD - Technical/structural
### Captured manifest and ownership contract
- A normalized `capture_outputs` declaration is sorted by normalized relative path.
  Paths are unique and may not be case-insensitive aliases or ancestor/descendant
  owners of another declared output. Only contained `.factory/reports/` paths qualify.
- Each `captured_outputs` item has `path`, `sha256`, `bytes`, and `data_base64`.
  Manifest order must exactly match the normalized declaration; `bytes` is an integer
  (not a boolean). Strict base64 decoding must produce exactly `bytes` bytes and the
  declared SHA-256. A per-check remaining-byte counter enforces the aggregate
  `max_output_bytes` budget, not a separate allowance for every report. The existing
  16-file and 1 MiB ceilings remain unchanged; encoded length is checked before decode.
- Validate the entire manifest before any host overwrite. Recheck destination
  containment, symlink/reparse-point exclusions, regular-file status and single-hardlink
  ownership before each export and again around the stable identity/digest read at
  final proof admission. Missing or changed identity, bytes or ownership rejects
  admission even if a previous export passed. This is local integrity checking,
  not protection from a hostile process with unrestricted host-write access.
- Protect the source/configuration inventory, declared inputs and dependency closure,
  oracle/intent/authority bindings, manifest and release contract, including references
  under the report namespace. Traverse referenced governance JSON once per normalized
  path, at most 500 files and 1 MiB per referenced file; overflow, unreadable JSON or
  malformed referenced governance JSON returns `E_PRE_PR_OUTPUT`. Opaque report JSON
  is not required to parse as governance JSON merely because its extension is `.json`;
  a recognized pre-PR/live-feedback/scheduler governance schema is protected rather
  than treated as an overwriteable report. Do not traverse capture declarations as
  protected input references or let these declarations erase actual input bindings.
- Contract: optional capture_outputs list on existing live/replay checks; receipt carries captured output manifest; host export independently verifies digest.
- Scope: senior_assurance.py, live_feedback.py, incremental_scheduler.py and existing tests.
- Existing read_only proofs without capture_outputs retain stable-output behavior.
- Capture precedes temporary workspace deletion, but host export and proof admission require the final cleanup-confirmed receipt. All report payloads require independent host digest and byte-count checks before host writes.
- Existing test owners: tests/test_senior_assurance.py and tests/test_change_review.py; no tests/test_live_feedback.py module exists or is proposed.
## SHOULD NOT - Implementation details
- No new module, dependency, store, cap increase, credential, provider or release authority.
- Existing agent-generated SpecLine approval metadata is historical local-integrity evidence, not authenticated human approval. Root recorded the owner's subsequent explicit architecture approval; merge and release remain separate decisions.
