# Spec: proof-continuity-ledger-v1

Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

Code Factory shall provide a repository-level, hash-bound audit receipt that
links a current Oracle Contract to a complete
`source -> obligation -> forbidden behavior -> gate -> test -> evidence -> decision`
chain for one exact revision. It shall treat AppForge as optional evidence, not
as the primary workflow, and it shall never execute, release, or self-approve.

### Declared facts

- `oracle_current`: the source Oracle Contract verifies with original intent and sources current.
- `authoritative_provenance_only`: chain rules are human-confirmed or trusted-source blocking/release rules.
- `critical_chain_complete`: every critical requirement, forbidden behavior, gate, and test occurs in a sealed chain row.
- `evidence_bound`: each evidence receipt matches declared schema, marker, digest field, workspace path, and revision when it declares one.
- `contradiction_reopens`: a hash-bound contradicted later observation yields `E_PROOF_CONTINUITY_REOPENED`, `BLOCKED`, and supervised review.
- `unknown_never_releases`: an inconclusive observation yields review required, not current/release-ready.
- `read_only_projection`: CLI status, Graph Ops, and MCP run no test, mutation, release, provider, or credential operation.

### Requirements (EARS)

- When `AUDIT_CHAIN_SEAL` receives a current Oracle Contract, a fixed-shape repository subject, authoritative chains, and hash-valid local evidence, the system shall write one immutable `PROOF_CONTINUITY_SEALED` receipt. [R1]
- If `AUDIT_CHAIN_GUARD` finds an unbound rule, advisory/agent provenance, missing critical chain element, stale evidence, revision mismatch, output collision, or out-of-scope path, the system shall refuse and write 0 receipts. [R2]
- When `LATER_OBSERVATION` records a contradiction against one sealed obligation, the system shall write `E_PROOF_CONTINUITY_REOPENED` with a causal chain, local incident, `BLOCKED` verdict, and `supervised` recommended autonomy. [R3]
- When `CONTINUITY_STATUS_REQUESTED` reads receipts, Graph Ops and MCP shall
  expose bounded read-only current/reopened counts without execution authority.
  [R4]

## SHOULD - Technical/structural

- API: `factory proof-continuity seal|observe|status`.
- Data schemas: `factory.proof-continuity-*.v1`.
- Inputs are workspace-local UTF-8 JSON under 1 MiB.
- Graph Ops links Oracle decision nodes to the continuity audit and later
  observations.

## Acceptance scenarios

```gherkin
Scenario: Seal a senior-engineering audit receipt
  Given a current Oracle Contract and hash-valid test evidence for one revision
  When an owner seals a complete continuity input
  Then the system writes PROOF_CONTINUITY_SEALED
  And it does not run a test, mutate code, release, or approve work

Scenario: Reopen when later evidence contradicts an obligation
  Given a sealed continuity receipt for a restore obligation
  When a named reviewer records hash-bound contradictory runtime evidence
  Then the system writes E_PROOF_CONTINUITY_REOPENED with BLOCKED
  And the recommended autonomy mode is supervised
```

## SHOULD NOT - Non-goals

- Do not decide whether evidence itself is truthful.
- Do not run an agent, a test, challenge, build, release, provider, or Apple action.
- Do not allow an agent-proposed policy to become blocking merely by entering it
  in an audit input.
