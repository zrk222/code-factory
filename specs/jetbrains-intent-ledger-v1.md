# Spec: jetbrains-intent-ledger-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core

### Description

FactoryLine Intent Ledger turns one explicitly confirmed, local behavioral promise for a native JetBrains Change List into a content-addressed record. It then projects the current Change List against that declared scope, existing Diff-to-Proof evidence, and proof gaps. It gives a developer or reviewer one fact-derived next proof without running tests, editing source, recalling memory bodies, approving a change, or performing an external action.

### User roles

- Developer: explicitly records a concise promise, non-goal, and negative case for one local Change List, then inspects its current evidence state.
- Reviewer: reads the same local ledger, its scope drift, fresh/stale proof state, and next proof before deciding independently.
- AI assistant: reads the narrow MCP projection; it cannot record, amend, approve, or execute the ledger.

### Decision facts

- `matching_intact_record`: whether the latest record for `change_list_name` has a valid canonical digest and is at most 256 KiB.
- `current_changed_paths`: sorted, de-duplicated, workspace-relative paths supplied by the selected local Change List.
- `declared_scope_paths`: sorted, de-duplicated workspace-relative paths stored in the matching record.
- `scope_escape_paths`: `current_changed_paths - declared_scope_paths`.
- `change_review_available`: whether Diff-to-Proof returned a valid analysis-only review.
- `stale_proof_ids`: declared proof identifiers returned by the current Diff-to-Proof review.
- `coverage_complete`: the Boolean requirement-coverage result returned by the current Diff-to-Proof review.

### Requirements (EARS)

- The system shall record an Intent Ledger only after the caller supplies a non-empty Change List name, at least one workspace-relative changed path, a named confirmer, one promise, one non-goal, one negative case, and an exact confirmation phrase.
- When a ledger is recorded, the system shall bind the declared path set, immutable intent fields, record creation time, and a canonical SHA-256 digest into one local JSON artifact below `.factory/intent-ledgers/`.
- When an active Change List is inspected, the system shall select only the latest intact local ledger with the same Change List name and calculate scope escape, stale-proof, coverage, and change-review availability from explicit local facts.
- When a current changed path is absent from the declared ledger scope, the system shall report `scope_escape` before lower-priority findings and shall not call the ledger review-ready.
- When the underlying Diff-to-Proof review reports `stale_proof_ids`, incomplete `coverage_complete`, or unavailable `change_review_available`, the system shall return the named finding as Intent Ledger state rather than infer success.
- When no matching ledger exists, the system shall return a machine-readable `uncontracted` state and a precise next action; it shall not create an implied promise.
- While a ledger is inspected through the CLI, MCP, or JetBrains UI, the system shall perform no source write, test execution, repair, approval, merge, publication, deployment, signing, messaging, credential, connector, or memory-recall action.
- If a ledger artifact is malformed, has an invalid digest, lies outside the workspace, or exceeds 256 KiB, the system shall return `intent_ledger_invalid` and name the rejected artifact without reading a fallback record.
- Where a JetBrains project has native Local Change Lists, the plugin shall pass only the selected list's explicit project-relative paths to the local CLI and shall require workspace confirmation before capture or inspection.
- Where no fully project-contained Change List is available, the plugin shall explain the blocker and shall not silently omit unavailable paths.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Capture a confirmed behavioral promise for a Change List
  Given current_changed_paths contains app/billing.py
  When a developer confirms a promise, non-goal, negative case, named confirmer, and the exact capture phrase
  Then FactoryLine writes one digest-bound Intent Ledger below .factory/intent-ledgers
  And the record contains only the declared local metadata and scope
  And no test, repair, approval, publish, deployment, or remote request ran

Scenario: Surface a scope escape before an outdated green result
  Given a valid Intent Ledger declares only app/billing.py
  And the current Change List also contains app/invoices.py
  When the ledger is inspected
  Then the first state is scope_escape for app/invoices.py
  And the next action is amend_or_split_change_list
  And the result is not review-ready

Scenario: Preserve invalidated proof instead of a green inference
  Given a valid Intent Ledger and a current Diff-to-Proof review with a stale proof
  When the ledger is inspected
  Then the result includes stale_proof and the bound proof identifier
  And the next action is rerun_stale_proof
  And no proof command is executed

Scenario: Use the JetBrains surface without broad indexing
  Given a JetBrains project with a selected native Change List
  When the user chooses Inspect Intent Ledger
  Then the plugin sends only that list's explicit project paths to the configured local factory executable
  And it renders the structured local result in the Intent Ledger tab
  And it does not inspect paths outside current_changed_paths, alter settings, or start an agent
```

## SHOULD — Technical/structural

- ADR references: existing `docs/PLAN_TO_PROOF_REVIEW.md`, `docs/FACTORY_CONTINUITY.md`, and `docs/REALITY_CHECK.md`.
- Data model: `factory.intent-ledger.v1` JSON record and `factory.intent-ledger-inspection.v1` projection, `change_list_name`, `current_changed_paths`, `declared_scope_paths`, `scope_escape_paths`, `change_review_available`, `stale_proof_ids`, `coverage_complete`, canonical SHA-256, a 256 KiB record limit, bounded local artifact count, and explicit authority.
- CLI: `factory intent capture` is a named-confirmation local write; `factory intent inspect` is read-only JSON/text output.
- MCP: `factory.intent_ledger` is read-only and accepts only an optional Change List name, changed paths, and base.
- UI: add an Intent Ledger Tool Window tab plus explicit Tools menu actions. Use selected Change List paths only and keep the analysis visually legible with a single next action.

## SHOULD NOT — Implementation details

- Do not use a model to decide ledger state, infer a missing intent, create test commands, or grade production readiness.
- Do not turn local Git contributors into team identity, approval, ownership, billing, productivity, or entitlement facts.
- Do not make Intent Ledger a default commit block or use it to mutate a Change List, source file, test, cache, index, remote workspace, or connector configuration.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `matching_intact_record` is false | `uncontracted`; next `capture_intent` |
| 2 | `scope_escape_paths` is non-empty | `scope_escape`; next `amend_or_split_change_list` |
| 3 | `change_review_available` is false | `change_review_unavailable`; next `inspect_change_set` |
| 4 | `stale_proof_ids` is non-empty | `stale_proof`; next `rerun_stale_proof` |
| 5 | `coverage_complete` is false | `coverage_incomplete`; next `complete_requirement_coverage` |
| 6 | `matching_intact_record` is true, `scope_escape_paths` is empty, `change_review_available` is true, `stale_proof_ids` is empty, and `coverage_complete` is true | `ready_for_human_review`; next `review_packet` |
