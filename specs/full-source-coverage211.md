# Spec: full-source-coverage211
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Provide an explicitly selected full-repository source-analysis profile. Account
for every eligible Python file using existing native discovery rules. Preserve
frozen precision studies and report behavioral uncertainty separately. The owner
delegated this coverage choice on 2026-10-21.

### User roles
- Developer requesting every eligible source file be accounted for.
- Reviewer checking source, coverage, uncertainty and resume evidence.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- The system shall emit `inventory_sha256` binding one sorted inventory row for every eligible Python file before returning findings.
- When analysis executes, the system shall emit `primary_results` containing exactly one native result per eligible path without target execution or dependency installation.
- The system shall emit `batch_primary_limit` as 460, emit at most 460 primary results per batch, and store pending paths for the next batch without repository truncation.
- The system shall emit `files_audited` separately from discovered, syntax-error, unreadable, oversized and pending counts and emit 100 percent audited coverage only when every discovered file is audited and the inventory is nonempty.
- If source content, configuration or discovery inventory changes, the system shall reject batch reuse with `SOURCE_DRIFT`; if scanner identity changes, the system shall reject reuse with SCANNER_DRIFT.
- When a saved batch is reused, the system shall verify source bindings, result digest and scanner identity and reject modified saved data with `INVALID_CHECKPOINT`.
- While global consumer and mutation closure is unverified, the system shall emit semantic coverage as `INCOMPLETE`, retain native risk severity and reject cross-batch exculpatory admission.
- The system shall emit report schema `factory.full-repository-scan.v1` and reject submission as a legacy bounded-scan completion receipt or release approval.
- When full-repository analysis executes, the system shall emit `target_execution` as false and reject target-source writes, preserving original Study209 and Study210 inputs and precision records.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Repository exceeds the bounded scanner profile
  Given a repository containing 461 eligible Python files
  When the full-repository profile completes its batches
  Then 461 primary rows exist with 0 pending paths and no duplicate primary path

Scenario: Parser failure remains visible
  Given 460 parseable Python files and 1 invalid Python file
  When the full-repository profile completes
  Then discovered is 461 and audited is 460 and syntax-error is 1
  And audited coverage is less than 100 percent

Scenario: Resume cannot reuse changed source
  Given a saved batch with an exact inventory digest
  When one source file changes before resume
  Then reuse is rejected with SOURCE_DRIFT

Scenario: Cross-batch consumer is unresolved
  Given a credential declaration with a consumer outside its analysis batch
  When global consumer closure is unverified
  Then native credential severity is retained and semantic coverage is INCOMPLETE

Scenario: Output contract and drift rejection
  Given a completed full-repository scan
  Then `inventory_sha256` binds the sorted source inventory
  And `primary_results` contains one result per eligible path
  And `batch_primary_limit` is 460
  And `files_audited` equals the count of successfully audited paths
  And the schema is `factory.full-repository-scan.v1`
  And `target_execution` is false
  And semantic coverage is `INCOMPLETE` when global consumer closure is unverified
  When one source file changes before resume
  Then `SOURCE_DRIFT` rejects reuse
  When one saved result digest is modified
  Then `INVALID_CHECKPOINT` rejects reuse
```

## SHOULD — Technical/structural
- Reuse existing native source readers, scanner and owners; add no production module.
- Keep architecture ceilings at 464 Python files and 133 core modules.
- Report measured timings separately from coverage; no speed gain follows from file counts.
- Record source-derived dependency edges separately from resolved runtime targets.

## SHOULD NOT — Implementation details
<!-- Leave the "how" to the plan/tasks unless it is a systemic invariant -->
- Do not add a second scanner, target executor or per-pattern proof-module tree.
- Do not equate accounted files with all behaviors checked or alter frozen evaluation inputs.

## Decision logic (factory candidates)
<!-- Ordered business rules over extracted facts. specline handoff compiles
     these via HSF instead of letting agents improvise them. -->
| # | if | then |
|---|----|------|
