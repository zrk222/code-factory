# Spec: oracle-firewall-v1
Status: draft
SpecFactor-target: 0.75-2.5

## MUST — Functional core
### Description
Prevent a coding agent from becoming the author, judge, and reviser of its own
definition of done.  Oracle Firewall seals source-bound requirements, gate
values, exceptions, negative cases, invariants, and declared tests before work
is admitted; classifies every item by provenance; blocks semantic weakening;
and projects the complete proof-of-the-oracle path into FactoryLine Mission
Control without granting Graph Ops execution or approval authority.

### User roles
- **Product owner:** names and approves the intended outcome and any change to
  a release-affecting oracle rule.
- **Worker agent:** may propose advisory rules and produce a bounded candidate;
  it cannot promote its own proposal or edit the sealed oracle.
- **Independent verifier:** evaluates a hash-bound implementation-targeted
  challenge result; it cannot edit the candidate or oracle.
- **Reviewer:** reads Oracle Mission Control, reviews a semantic contract diff,
  and decides whether to create a separately sealed successor contract.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- When `ORACLE_CONTRACT_SEAL_REQUESTED` is detected, the system shall return `ORACLE_CONTRACT_SEALED` after storing one `factory.oracle-contract.v1` with named approval, source hashes, declared scope paths, and provenance-labelled requirements, thresholds, exceptions, negative cases, invariants, and tests.
- When `ORACLE_HANDOFF_CAPTURE_REQUESTED` is detected, the system shall return `ORACLE_HANDOFF_CAPTURED` after storing one `factory.intent-handoff.v1` with exact original-intent source bytes, source SHA-256, declared handing-off agent identity, and no agent-authored paraphrase substitution.
- When `ORACLE_HANDOFF_BOUND` is detected, the system shall return `ORACLE_CONTRACT_SEALED` only when every blocking or non-advisory requirement, threshold, invariant, negative case, and test cites the exact captured original-intent source ID.
- When `ORACLE_PROVENANCE_SUBMITTED` is detected, the system shall return `ORACLE_PROVENANCE_INVALID` for an origin other than `human_confirmed`, `trusted_source`, `observed_production`, or `agent_proposed`.
- When `ORACLE_ADVISORY_ORIGIN` is detected, the system shall return `ORACLE_PROVENANCE_INVALID` unless the item effect is `advisory`.
- When `ORACLE_TRUSTED_SOURCE_BOUND` is detected, the system shall store each
  referenced workspace-relative source path and SHA-256 in `ORACLE_CONTRACT_SEALED`.
- If `ORACLE_CONTRACT_SOURCE_STALE` is detected, then the system shall return `ORACLE_ADMISSION_PAUSED` with marker `ORACLE_CONTRACT_SOURCE_STALE`.
- When `ORACLE_CONTRACTS_COMPARED` is detected, the system shall return one `factory.oracle-drift.v1` report with before/after values, source justifications, and verdict `CLEAR`, `REVIEW_REQUIRED`, or `BLOCKED`.
- If `ORACLE_WEAKENING_DETECTED` is detected, then the system shall return `E_ORACLE_WEAKENING` with verdict `BLOCKED` for a removed required scenario, negative case, invariant, or test; an added exception; a widened tolerance; a lowered threshold; a relaxed gate effect; or a rewritten negative proof.
- When `ORACLE_CHALLENGE_COMPILE_REQUESTED` is detected, the system shall return `ORACLE_CHALLENGE_COMPILED` with one `factory.oracle-challenge.v1` containing one implementation-targeted counterfactual for each critical requirement, threshold, negative case, and invariant.
- If `ORACLE_CHALLENGE_FAILURE` is detected, then the system shall return `ORACLE_CHALLENGE_FAILED`.
- When `ORACLE_AUTONOMY_REQUESTED` is detected, the system shall return
  `ORACLE_ADMISSION_READY` only when the contract verifies, has no unresolved
  advisory proposal, and matches the pre-run contract digest.
- If `ORACLE_GOVERNED_RUN_WEAKENING` is detected, then the system shall store an `E_ORACLE_WEAKENING` incident capsule and return `ORACLE_AUTONOMY_DEMOTED` with tier `human_controlled`.
- When `ORACLE_GRAPH_PROJECT_REQUESTED` is detected, the system shall return `ORACLE_GRAPH_PROJECTED` with typed, local, read-only `Source -> obligation -> forbidden behavior -> gate -> test -> evidence -> decision` facts and approval plus execution false.
- When `ORACLE_APPFORGE_AUTHORITY_REQUESTED` is detected, the system shall return `APPFORGE_ORACLE_AUTHORITY_VERIFIED` only when one candidate-bound AppForge authority receipt binds the sealed Oracle contract, named human reviewer, and hash-verified policy sources.
- When `ORACLE_CODEX_METADATA_AUDIT_REQUESTED` is detected, the system shall return `CODEX_METADATA_AUDITED` from explicit workspace-local metadata only, and shall not import prompts, credentials, raw tool output, or home-directory Codex records.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Agent-proposed gate cannot self-authorize a non-advisory effect
  Given a sealed contract with one `agent_proposed` threshold
  When the threshold requests a non-advisory effect
  Then contract sealing rejects the candidate

Scenario: Stale original source pauses admission
  Given `ORACLE_CONTRACT_SOURCE_STALE`
  When admission verifies the pre-run contract
  Then `ORACLE_ADMISSION_PAUSED`

Scenario: Semantic weakening is named and blocked
  Given `ORACLE_WEAKENING_DETECTED`
  When the prior and candidate Oracle contracts are compared
  Then `E_ORACLE_WEAKENING`

Scenario: Original intent remains the source of truth across an agent handoff
  Given `ORACLE_HANDOFF_CAPTURED` for the original user request bytes
  And a candidate contract citing that handoff source ID
  When the contract is sealed and an implementation challenge is verified
  Then the source, obligation, gate, test, evidence, and decision remain linked
  And an agent paraphrase cannot replace the original-intent hash

Scenario: Semantic gate weakening blocks promotion
  Given a prior sealed contract with a required negative case
  And a candidate contract that removes that negative case
  When the contracts are compared
  Then the report returns `E_ORACLE_WEAKENING`
  And the verdict is `BLOCKED`

Scenario: The Shadow Oracle Loop rejects a survivor
  Given one verified sealed contract and implementation-targeted challenge plan
  When an independent challenge receipt reports one surviving case
  Then the result is non-passing
  And no contract or source file is modified

Scenario: Oracle drift demotes autonomous work
  Given an agent with otherwise sufficient autonomous evidence
  And an oracle weakening incident for that agent
  When FactoryLine derives the agent license
  Then the tier is `human_controlled`

Scenario: Mission Control projects proof of the oracle without authority
  Given one sealed contract, one drift report, and one challenge result
  When Graph Ops loads the workspace
  Then it renders source, obligation, forbidden behavior, gate, test, evidence, and decision nodes
  And its authority keeps approval and execution false

Scenario: AppForge submission cannot substitute policy prose for Oracle authority
  Given an AppForge submission dossier that requires Oracle authority
  When the candidate-bound authority receipt is absent or stale
  Then submission assurance fails closed
  And it does not claim App Store approval

Scenario: AppForge authority has a distinct verified result
  Given `ORACLE_APPFORGE_AUTHORITY_REQUESTED`
  When the candidate, reviewer, sources, and contract are hash-bound
  Then `APPFORGE_ORACLE_AUTHORITY_VERIFIED`

Scenario: Historical run state is not promoted into a live gate
  Given a workspace metadata file with a terminal state but no intent hash or verifier receipt
  When Code Factory audits the declared workspace metadata
  Then it reports unbound historical state
  And it does not use that state as Oracle, admission, or release evidence

Scenario: Codex metadata audit stays inside the workspace boundary
  Given `ORACLE_CODEX_METADATA_AUDIT_REQUESTED`
  When explicit workspace-local metadata paths are audited
  Then `CODEX_METADATA_AUDITED`
```

## SHOULD — Technical/structural
- ADR references: `docs/ORACLE_FIREWALL.md` and `docs/GRAPH_OPS.md`.
- Data model: immutable JSON artifacts under `.factory/oracles/handoffs/`,
  `.factory/oracles/contracts/`,
  `.factory/oracles/drifts/`, `.factory/oracles/challenges/`, and
  `.factory/oracles/incidents/`.
- API contract: `factory oracle handoff|seal|verify|diff|challenge|challenge-verify|admit|incident|init|status`;
  Graph Ops, FactoryLine, MCP, and WebMCP project read-only local status.
- AppForge submission assurance may require a candidate-bound `factory.appforge.oracle-authority-receipt.v1`; it is evidence only and does not submit an app.
- Codex metadata audit accepts only explicit workspace-local paths and returns provenance findings without ingesting private conversations or credentials.

## SHOULD NOT — Implementation details
- Do not infer real-world identity, source trust, user intent, or approval from
  an agent-provided label.
- Do not treat a contract digest, plan, Graph Ops node, or challenge receipt as
  proof that a worker executed, that an implementation is correct, or that a
  release is approved.
- Do not let a candidate code diff modify or reseal the pre-run oracle contract.

## Decision logic (factory candidates)
<!-- Ordered business rules over extracted facts. specline handoff compiles
     these via HSF instead of letting agents improvise them. -->
| # | if | then |
|---|----|------|
| 1 | `ORACLE_CONTRACT_SEAL_REQUESTED` | return `ORACLE_CONTRACT_SEALED` |
| 2 | `ORACLE_HANDOFF_CAPTURE_REQUESTED` | return `ORACLE_HANDOFF_CAPTURED` |
| 3 | `ORACLE_HANDOFF_BOUND` | return `ORACLE_CONTRACT_SEALED` only with source traceability |
| 4 | `ORACLE_PROVENANCE_SUBMITTED` | return `ORACLE_PROVENANCE_INVALID` when origin is unsupported |
| 5 | `ORACLE_ADVISORY_ORIGIN` | return `ORACLE_PROVENANCE_INVALID` |
| 6 | `ORACLE_TRUSTED_SOURCE_BOUND` | store the source path and SHA-256 |
| 7 | `ORACLE_CONTRACT_SOURCE_STALE` | return `ORACLE_ADMISSION_PAUSED` |
| 8 | `ORACLE_CONTRACTS_COMPARED` and semantic weakening exists | return `E_ORACLE_WEAKENING` with `BLOCKED` |
| 9 | `ORACLE_CONTRACTS_COMPARED` and a non-weakening review difference exists | return `REVIEW_REQUIRED` drift facts |
| 10 | `ORACLE_CONTRACTS_COMPARED` and no semantic difference exists | return `CLEAR` drift facts |
| 11 | `ORACLE_CHALLENGE_COMPILE_REQUESTED` | return `ORACLE_CHALLENGE_COMPILED` |
| 12 | `ORACLE_CHALLENGE_FAILURE` | return `ORACLE_CHALLENGE_FAILED` |
| 13 | `ORACLE_AUTONOMY_REQUESTED` | return `ORACLE_ADMISSION_READY` only for an eligible contract |
| 14 | `ORACLE_GOVERNED_RUN_WEAKENING` | return `ORACLE_AUTONOMY_DEMOTED` |
| 15 | `ORACLE_GRAPH_PROJECT_REQUESTED` | return `ORACLE_GRAPH_PROJECTED` read-only facts |
