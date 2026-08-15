# Spec: proofsearch-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core
### Description
ProofSearch converts one verified Graph Forensics divergence into a bounded
proof slice, then deterministically compares supplied repair candidates. It
selects the smallest eligible repair and explains why every loser was rejected
without generating, applying, committing, publishing, or deploying code.

### User roles
- Operator supplying sealed lineage and local candidate evidence.
- Human reviewer deciding whether a recommended repair may be applied.

### Requirements (EARS)
- When two sealed lineage receipts diverge, the system shall return `PROOFSEARCH_PLAN_SEALED` with the first divergence, authorized changed paths, exact Graph Impact proof slice, and a canonical SHA-256 digest. [R1]
- The system shall return `PROOFSEARCH_CANDIDATE_BOUNDS_ENFORCED` after accepting 2 through 12 candidates and rejecting larger, empty, duplicate, malformed, or unsealed candidate sets. [R2]
- When a candidate has a failed required proof, a mismatched receipt hash, a declared proof status unsupported by the receipt outcome, an unverifiable receipt outcome, an inexact mutation score, a changed path outside the plan, declared test weakening, declared error suppression, or declared scope expansion, the system shall return `PROOFSEARCH_CANDIDATE_REJECTED` with the candidate as ineligible and a deterministic rejection reason. [R3]
- When one or more candidates are eligible, the system shall return `PROOFSEARCH_WINNER_VERIFIED` and select the deterministic minimum tuple of risk score, changed lines, proof elapsed milliseconds, measured tokens, measured cost, and candidate identifier. [R4]
- When no candidate is eligible, the system shall return `PROOFSEARCH_NO_ELIGIBLE_CANDIDATE` and no winner. [R5]
- The system shall return `PROOFSEARCH_LOSERS_EXPLAINED` with a deterministic rejection or loss reason for every non-winning candidate. [R6]
- When an exact paired baseline is absent, the system shall return `PROOFSEARCH_SAVINGS_UNMEASURED` with null time, token, cost, and productivity savings. [R7]
- The system shall return `PROOFSEARCH_AUTHORITY_RETAINED` with false values in every plan and evaluation for code generation, command execution, workspace mutation, test mutation, checkpoint mutation, approval, merge, publication, deployment, signing, messaging, credential, and connector authority. [R8]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Smallest fully proven repair wins
  Given one sealed ProofSearch plan and three hash-bound candidates
  When two candidates pass every required proof and kill every declared mutant
  Then the result returns PROOFSEARCH_WINNER_VERIFIED and selects the deterministic minimum tuple of risk score, changed lines, proof elapsed milliseconds, measured tokens, measured cost, and candidate identifier

Scenario: Divergence seals one bounded plan
  Given two sealed lineage receipts diverge
  When ProofSearch creates a plan
  Then the result returns PROOFSEARCH_PLAN_SEALED with the first divergence, authorized changed paths, exact Graph Impact proof slice, and a canonical SHA-256 digest

Scenario: Candidate collection stays bounded
  Given a candidate set contains 2 through 12 unique sealed candidates
  When ProofSearch validates the candidate set
  Then the result returns PROOFSEARCH_CANDIDATE_BOUNDS_ENFORCED and the candidate set is accepted while larger, empty, duplicate, malformed, or unsealed candidate sets are rejected

Scenario: Candidate with surviving mutants is rejected
  Given one candidate whose mutation killed count is below its total
  When ProofSearch evaluates the candidate set
  Then the result returns PROOFSEARCH_CANDIDATE_REJECTED with the candidate ineligible and a deterministic rejection reason

Scenario: Candidate exceeds approved paths
  Given one candidate changes a path absent from the plan
  When ProofSearch evaluates the candidate set
  Then the result returns PROOFSEARCH_CANDIDATE_REJECTED with the candidate ineligible and a deterministic rejection reason

Scenario: No repair has complete proof
  Given every candidate is ineligible
  When ProofSearch evaluates the candidate set
  Then the result returns PROOFSEARCH_NO_ELIGIBLE_CANDIDATE and no winner

Scenario: Every loser is explained
  Given one winning candidate and two non-winning candidates
  When ProofSearch returns the evaluation
  Then the result returns PROOFSEARCH_LOSERS_EXPLAINED and every non-winning candidate has a deterministic rejection or loss reason

Scenario: Unmeasured savings remain unknown
  Given no exact paired baseline metrics
  When ProofSearch evaluates an eligible winner
  Then the result returns PROOFSEARCH_SAVINGS_UNMEASURED and time, token, cost, and productivity savings are null

Scenario: Authority stays human-owned
  Given a verified winner
  When ProofSearch returns the evaluation
  Then the result returns PROOFSEARCH_AUTHORITY_RETAINED and code generation, command execution, workspace mutation, test mutation, checkpoint mutation, approval, merge, publication, deployment, signing, messaging, credential, and connector authority are false
```

## SHOULD - Technical and structural
- ADR references: docs/PROOFSEARCH.md and docs/GRAPH_OPS.md
- Data models: `factory.proofsearch-plan.v1`, `factory.proofsearch-request.v1`, and `factory.proofsearch-evaluation.v1`
- API contract: `create_proofsearch_plan`, `evaluate_proofsearch`, and `verify_proofsearch_evaluation`
- Input encoding: UTF-8; generic text fields are at most 320 characters and candidate identifiers are at most 120 characters.
- Numeric bounds: non-negative integer evidence values are at most 10^12; candidate risk is at most 100, changed lines are at most 1000000, mutation killed and total counts are each at most 100000, each candidate has at most 64 proofs, and a plan has at most 256 changed paths.
- Ordering: the winner is the first eligible candidate at zero-based index 0 after the declared total ordering.

## SHOULD NOT - Implementation details
- The feature should not invoke models, execute candidate commands, create or remove worktrees, modify tests, apply patches, or infer missing performance data.

## Decision logic (factory candidates)
Reject structurally unsafe candidates first. Rank remaining candidates by the
documented total ordering. Never trade a failed proof or surviving mutant for
lower latency, token use, cost, or changed-line count.
