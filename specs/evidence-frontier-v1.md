# Spec: evidence-frontier-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Evidence Frontier turns one verified ProofSearch evaluation into a bounded,
read-only recommendation for the next evidence-producing experiment. It helps
an operator distinguish eligible repair candidates before any patch, command,
checkpoint, approval, merge, publication, or deployment occurs.

### User roles

- Operator supplies a hash-bound ProofSearch evaluation and bounded experiment
  hypotheses.
- Human reviewer decides whether a separately authorized runner may execute a
  proposed experiment.

### Declared facts

- `evaluation_valid`: whether the referenced evaluation verifies against current
  local evidence.
- `eligible_candidate_count`: the number of evaluation candidates marked eligible.
- `prediction_contract_valid`: whether each experiment predicts `pass`, `fail`,
  or `unknown` for every eligible candidate and no other candidate.
- `separation_count`: the count of unordered eligible-candidate pairs with two
  different non-unknown predictions.
- `experiment_count`: the number of supplied experiments.
- `max_experiments`: the caller-declared integer bound from 1 through 64.
- `measured_elapsed_ms`: a nullable historical integer from 0 through
  1,000,000 milliseconds, available only when the caller bound it to evidence.

### Requirements (EARS)

- When `evaluation_valid` is true and `eligible_candidate_count` is from 2 through 12, the system shall write one `factory.evidence-frontier.v1` receipt whose SHA-256 digest covers the evaluation, every experiment, the deterministic ordering, the selected next experiment, and every authority value.
- When `prediction_contract_valid` is true, the system shall return `separation_count` as the number of unordered eligible-candidate pairs with two different non-unknown predicted outcomes.
- When two or more experiments have equal `separation_count`, the system shall return the experiment with the lower non-null `measured_elapsed_ms` first; if only one `measured_elapsed_ms` value is non-null, the system shall return that experiment first; remaining ties shall return the lexicographically smallest experiment identifier.
- If every `separation_count` equals 0, the system shall return `EVIDENCE_FRONTIER_NO_DISCRIMINATING_EXPERIMENT`, return `next_experiment` as null, and return null for time, token, cost, and productivity savings.
- When `experiment_count` exceeds `max_experiments`, the system shall reject the request before writing an output artifact.
- If `evaluation_valid` is false, `eligible_candidate_count` is less than 2, `prediction_contract_valid` is false, an identifier is duplicated, a path escapes the workspace, a digest changes, or a numeric field is malformed, the system shall reject the request before writing an output artifact.
- The system shall return `false` for command execution, workspace mutation, checkpoint mutation, approval, merge, publication, deployment, signing, messaging, credential, connector, and code-generation authority in every result.
- When a sealed Evidence Frontier receipt or its bound evaluation changes bytes, the system shall return verification `valid` as false and a digest-mismatch error.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: A targeted experiment separates the most viable repairs
  Given one verified ProofSearch evaluation has three eligible candidates
  And one bounded experiment predicts pass, fail, and fail for those candidates
  When the operator plans an Evidence Frontier
  Then that experiment is selected as next_experiment
  And its separation_count is 2
  And every execution and release authority remains false

Scenario: An experiment cannot distinguish the candidate set
  Given every proposed experiment has matching or unknown predictions
  When the operator plans an Evidence Frontier
  Then next_experiment is null
  And the marker is EVIDENCE_FRONTIER_NO_DISCRIMINATING_EXPERIMENT
  And no savings values are reported

Scenario: A sealed evaluation changes after planning
  Given an Evidence Frontier receipt bound to a ProofSearch evaluation
  When the evaluation bytes change
  Then Evidence Frontier verification returns valid false
  And reports the bound evaluation digest mismatch
```

## SHOULD - Technical and structural

- ADR references: `docs/EVIDENCE_FRONTIER.md`, `docs/GRAPH_OPS.md`, and
  `docs/PROOFSEARCH.md`.
- Data model: `factory.evidence-frontier-request.v1` and
  `factory.evidence-frontier.v1`.
- API contract: `plan_evidence_frontier(root, request_path, out)` and
  `verify_evidence_frontier(root, frontier_path)`.
- Graph Ops shall render verified frontiers as a distinct typed lane with one
  disabled execution control and read-only copy, export, and guardrail actions.

## SHOULD NOT - Implementation details

- The feature should not invoke a model, execute a command, create a worktree,
  mutate code or tests, fork a checkpoint, approve a repair, or infer evidence
  that was not supplied.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `evaluation_valid` is false | reject the request |
| 2 | `eligible_candidate_count` is less than 2 | reject the request |
| 3 | `prediction_contract_valid` is false | reject the request |
| 4 | every `separation_count` equals 0 | return no discriminating experiment |
| 5 | one or more `separation_count` values exceed 0 | select by descending separation, measured duration availability, ascending measured duration, then identifier |
