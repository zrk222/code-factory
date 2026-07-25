# Spec: assembly-continue-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Code Factory shall provide one state-aware continuation surface for existing
repositories. It shall infer or accept a feature, inspect SpecLine, ForgeLine,
HSF, Prestige, and Factory receipt state, run only safe local deterministic
steps, stop at a true human-owned boundary, and emit automatic measurement
evidence.

### User roles

- Local developer or coding agent continuing an existing feature.
- Human reviewer responsible for spec, architecture, implementation, or release decisions.
- Release maintainer exporting privacy-safe aggregate evidence.

### Requirements (EARS)

- The system shall return marker `ASSEMBLY_CONTINUE_COMMAND` after accepting `factory continue [feature] --root .`. [R1]
- When the feature argument is absent and exactly one active feature is discoverable, the system shall return marker `FEATURE_AUTO_SELECTED` with the discovered feature name. [R2]
- If zero or multiple active features are discoverable, the system shall return marker `FEATURE_SELECTION_REQUIRED` with a bounded candidate list and no stage mutation. [R3]
- The system shall return marker `SSAT_PATH_RESOLVED` with an exact contract path from the repository root or `specs/` and shall prefer a non-adoption contract. [R4]
- When a safe deterministic stage is ready, the system shall return marker `SAFE_STAGE_EXECUTED` after executing the named stage and before evaluating the next stage. [R5]
- When human authorship or approval is required, the system shall return marker `HUMAN_BOUNDARY_EXPLICIT`, terminal state `waiting_for_human`, a typed reason, and exactly one concise next action. [R6]
- If a stage fails, the system shall return marker `ASSEMBLY_HALTED_EXACT` with terminal state `halted`, the earliest failing stage, and a non-zero exit status. [R7]
- When a continuation is waiting for a human, the system shall return marker `WAITING_EXIT_DISTINCT`, exit status 3, and terminal state `waiting_for_human`. [R8]
- The system shall return marker `HUMAN_OUTPUT_COMPACT` with a compact human CLI status card and shall emit full stage JSON only with `--json`. [R9]
- When a non-dry continuation ends, the system shall return marker `ASSEMBLY_RUN_RECEIPTED` after atomically writing exactly 1 run receipt containing elapsed milliseconds, stage and command counts, a retry count of 0 runs or more, terminal state, result byte count, and explicitly classified token and cost quality. [R10]
- If adapter usage is not supplied, the system shall return marker `UNKNOWN_USAGE_PRESERVED` after storing token and cost values as null with quality `unknown` and shall emit no savings value. [R11]
- The system shall return marker `PUBLIC_METRICS_AGGREGATE_SAFE` with a privacy-safe aggregate containing no feature names, repository paths, logs, prompts, or receipt bodies. [R12]
- The system shall return marker `STUDIO_ASSEMBLY_CONTAINED` after rendering a Factory Studio Assembly mode backed by the same continuation function and a token-protected `/api/continue` endpoint. [R13]
- The system shall return marker `STUDIO_AUTHORITY_UNCHANGED` after rejecting Factory Studio listener addresses other than `127.0.0.1` and rejecting deploy, publish, credential, signing, and external-message actions. [R14]
- The system shall return marker `ASSEMBLY_BACKWARD_COMPATIBLE` after parsing existing `factory assemble` JSON fields and legacy meter ledger records without migration. [R15]
- The system shall return marker `RELEASE_021_SYNCHRONIZED` after identifying version 0.21.0 in release metadata, editor artifacts, PyPI package metadata, the Hugging Face surface, and public documentation. [R16]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Continue one existing feature to a human boundary
  Given one feature with an approved spec and an expanded ForgeLine state
  When the operator runs factory continue
  Then the command selects that feature without prompting
  And reports waiting_for_human with exactly one architecture approval action
  And exits with status 3

Scenario: Refuse ambiguous continuation
  Given two active features in the repository
  When the operator runs factory continue without a feature
  Then no factory stage is executed
  And the response contains both candidates
  And the command exits non-zero

Scenario: Preserve unknown usage
  Given no adapter token report
  When a continuation receipt is written
  Then token and cost values are null
  And their evidence quality is unknown

Scenario: Export publication-safe evidence
  Given continuation receipts for named private features
  When the operator exports aggregate metrics
  Then the export contains totals and rates
  And it contains no feature names, paths, logs, or prompts

Scenario: Continue from Studio
  Given a loopback Factory Studio session token
  When the operator submits an Assembly continuation
  Then Studio returns the same terminal state and next action as the CLI
  And an invalid token is rejected

Scenario: Every requirement has an observable validator marker
  Given the Assembly Continue contract
  When strict validator mutation runs
  Then contract markers include `ASSEMBLY_CONTINUE_COMMAND`, `FEATURE_AUTO_SELECTED`, `FEATURE_SELECTION_REQUIRED`, `SSAT_PATH_RESOLVED`, `SAFE_STAGE_EXECUTED`, `HUMAN_BOUNDARY_EXPLICIT`, `ASSEMBLY_HALTED_EXACT`, `WAITING_EXIT_DISTINCT`, `HUMAN_OUTPUT_COMPACT`, `ASSEMBLY_RUN_RECEIPTED`, `UNKNOWN_USAGE_PRESERVED`, `PUBLIC_METRICS_AGGREGATE_SAFE`, `STUDIO_ASSEMBLY_CONTAINED`, `STUDIO_AUTHORITY_UNCHANGED`, `ASSEMBLY_BACKWARD_COMPATIBLE`, and `RELEASE_021_SYNCHRONIZED`
```

## SHOULD - Technical/structural

- ADR references: `adr/assembly-continue-v1.md`
- Data model: `factory.assembly-run.v1` and `factory.assembly-metrics.public.v1`.
- API contract: local `POST /api/continue`, protected by the existing Studio session token.

## SHOULD NOT - Implementation details

- No background daemon, hosted telemetry upload, credential discovery, or implicit release action.
- No token estimates derived from output characters.
- No feature selection by most-recent filesystem time when selection is ambiguous.

## Decision logic (factory candidates)

This orchestration surface does not define an HSF business-decision candidate.
Its branch behavior is fully specified by R2, R3, R7, and R8 and remains in the
build-time controller.
