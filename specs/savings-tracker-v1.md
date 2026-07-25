# Spec: savings-tracker-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Code Factory shall provide a local paired savings tracker that compares an
exact baseline observation with an exact Factory observation. It shall compute
time, token, and cost deltas only for supplied exact fields, require
hash-bound outcome-equivalence evidence before computing productivity gain, and
export publication-safe aggregates without private pair identifiers or paths.

### User roles

- Local developer or coding agent recording a paired observation.
- Human reviewer confirming that baseline and Factory outcomes are equivalent.
- Release maintainer exporting aggregate sample evidence.

### Requirements (EARS)

- The system shall return marker `SAVINGS_RECORD_COMMAND` after accepting `factory savings record checkout-2026-07-25` with exact baseline and Factory elapsed milliseconds. [R1]
- The system shall return marker `PAIR_ID_VALIDATED` after accepting only a 1-to-80-character lowercase identifier containing letters, digits, dots, underscores, or hyphens. [R2]
- When exact baseline and Factory values are supplied for a metric, the system shall return marker `SIGNED_DELTA_COMPUTED` with signed time, token, or cost savings equal to baseline minus Factory. [R3]
- If an optional token or cost value is absent from either side, the system shall return marker `UNKNOWN_PAIR_FIELD_PRESERVED` with the corresponding delta and rate as null. [R4]
- When baseline and Factory elapsed milliseconds are positive, the system shall return marker `TIME_SAVINGS_RATE_EXACT` with time-savings rate equal to signed time savings divided by baseline elapsed milliseconds. [R5]
- The system shall return marker `EQUIVALENCE_EVIDENCE_HASHED` and marker `PRODUCTIVITY_GAIN_EXACT` only after `--equivalent-outcome` supplies an existing evidence file, storing its SHA-256 and computing productivity gain as baseline elapsed milliseconds divided by Factory elapsed milliseconds minus 1. [R6]
- If equivalence evidence is absent, missing, or not explicitly asserted, the system shall return marker `PRODUCTIVITY_GAIN_WITHHELD` with productivity gain null and a typed reason. [R7]
- When a pair is recorded, the system shall return marker `SAVINGS_PAIR_RECEIPTED` after atomically writing exactly 1 private receipt under `.factory/savings/` using schema `factory.savings-pair.v1`. [R8]
- If a pair identifier already exists, the system shall return marker `PAIR_OVERWRITE_REFUSED`, make no mutation, and require explicit `--replace` to overwrite it. [R9]
- The system shall return marker `SAVINGS_REPORT_AGGREGATE_SAFE` with schema `factory.savings-report.public.v1`, pair counts, exact-field coverage, signed totals, and weighted rates over at most 10000 valid local pair receipts per report while excluding 8 private field classes: pair identifiers, feature names, paths, commands, prompts, logs, evidence digests, and receipt bodies. [R10]
- The system shall return marker `SAVINGS_NEGATIVE_VISIBLE` after preserving negative savings and productivity values without clamping or relabeling them as gains. [R11]
- The system shall return marker `SAVINGS_STUDIO_CONTAINED` after exposing savings recording and reporting through token-protected loopback Factory Studio endpoints with no publish, deploy, sign, credential, connector, or external-message authority. [R12]
- The system shall return marker `SAVINGS_EDITOR_VISIBLE` after exposing the aggregate savings report in VS Code and supported JetBrains IDEs through explicit local commands. [R13]
- The system shall return marker `SAVINGS_BACKWARD_COMPATIBLE` after reading existing Assembly run receipts and public metrics without migration or reinterpretation. [R14]
- The system shall return marker `RELEASE_022_SYNCHRONIZED` after identifying version 0.22.0 in package, editor, citation, archive, hosted, and public release metadata. [R15]

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Record a paired exact observation
  Given a baseline of 600000 elapsed milliseconds and 12000 tokens
  And a Factory observation of 300000 elapsed milliseconds and 8000 tokens
  When the operator records the pair
  Then time saved is 300000 milliseconds
  And token savings are 4000
  And time savings rate is 0.5

Scenario: Withhold causal productivity without equivalence evidence
  Given exact baseline and Factory elapsed milliseconds
  When the operator records no outcome-equivalence evidence
  Then productivity gain is null
  And the receipt explains that equivalence evidence is required

Scenario: Compute productivity with hash-bound equivalence evidence
  Given exact positive elapsed measurements
  And an existing validation receipt proving equivalent outcomes
  When the operator explicitly asserts equivalent outcomes
  Then the evidence SHA-256 is stored
  And productivity gain is computed from the paired elapsed measurements

Scenario: Preserve a regression
  Given the Factory observation consumes more time and tokens than baseline
  When the pair is recorded
  Then time and token savings are negative
  And the report does not clamp either value to zero

Scenario: Export publication-safe aggregates
  Given private savings pairs with internal identifiers and evidence paths
  When the operator exports the public savings report
  Then aggregate totals and coverage are present
  And pair identifiers and evidence paths are absent

Scenario: Every requirement has an observable validator marker
  Given the Savings Tracker contract
  When strict validator mutation runs
  Then contract markers include `SAVINGS_RECORD_COMMAND`, `PAIR_ID_VALIDATED`, `SIGNED_DELTA_COMPUTED`, `UNKNOWN_PAIR_FIELD_PRESERVED`, `TIME_SAVINGS_RATE_EXACT`, `EQUIVALENCE_EVIDENCE_HASHED`, `PRODUCTIVITY_GAIN_EXACT`, `PRODUCTIVITY_GAIN_WITHHELD`, `SAVINGS_PAIR_RECEIPTED`, `PAIR_OVERWRITE_REFUSED`, `SAVINGS_REPORT_AGGREGATE_SAFE`, `SAVINGS_NEGATIVE_VISIBLE`, `SAVINGS_STUDIO_CONTAINED`, `SAVINGS_EDITOR_VISIBLE`, `SAVINGS_BACKWARD_COMPATIBLE`, and `RELEASE_022_SYNCHRONIZED`
```

## SHOULD - Technical/structural

- ADR references: `adr/savings-tracker-v1.md`.
- Data models: `factory.savings-pair.v1` and `factory.savings-report.public.v1`.
- API contract: local token-protected `POST /api/savings` and `GET /api/savings`.

## SHOULD NOT - Implementation details

- No inferred token counts from text length, cached-input rate, or session totals.
- No productivity percentage from unmatched runs or unverified output quality.
- No hosted telemetry upload, background tracking, command interception, or implicit publication.
- No absolute-value conversion, zero-clamping, or removal of negative results.

## Decision logic (factory candidates)

This tracker performs deterministic arithmetic over owner-supplied exact facts.
It is not an HSF business-decision candidate.
