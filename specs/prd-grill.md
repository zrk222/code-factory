# Spec: prd-grill
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Provide a local, deterministic PRD clarification stage before SpecLine
optimization and Product Graph compilation. It turns only explicitly observed
PRD gaps into a small dependency-safe question frontier with recommendations,
source binding, and a reviewable Markdown artifact. It never invents product
answers, edits the input PRD, runs an agent, or creates external effects.

### User roles
- Product owner: resolves product decisions before implementation.
- Product engineer: converts an ambiguous PRD into a reviewable product
  contract before compilation.
- Reviewer: verifies the question scope, source hash, recommendations, and
  unresolved decisions before approving a revised PRD.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- The system shall store schema `factory.prd_grill.v1` with the UTF-8 source SHA-256, explicitly observed Product Graph gaps, local repository facts, and a deterministic question frontier.
- When quick mode runs, the system shall emit `question_frontier` with no more than **3** unresolved decision questions; when deep mode runs, it shall emit no more than **5** unresolved decision questions.
- The system shall emit a `recommendation`, target PRD section, evidence, and dependency list for every question without treating the recommendation as a user decision.
- When a question depends on an unresolved prerequisite decision, the system shall store the dependent question with status `deferred` and omit it from the current question frontier.
- If a PRD is absent, invalid UTF-8, empty, or exceeds the established product PRD bound, the system shall reject the input with `PRD_ENCODING_INVALID` or the matching input error without writing an artifact.
- The system shall store a reviewable Markdown question sheet at `answer_sheet_path` with answer stubs and an explicit statement that the source PRD remains unchanged.
- When no unresolved questions remain and the caller confirms shared understanding, the system shall store marker `PRD_GRILL_SHARED_UNDERSTANDING_CONFIRMED` without authorizing implementation.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: surface only the first safe PRD decisions
  Given a PRD with no requirements or acceptance scenario
  When PRD Grill runs in quick mode
  Then the `question_frontier` contains at most three records with source evidence
  And acceptance evidence remains `deferred` until the requirements decision is resolved
  And the input PRD bytes remain unchanged

Scenario: produce a reviewable clarification sheet
  Given a PRD with an observed trust-boundary gap
  When PRD Grill runs in deep mode
  Then its Markdown artifact includes the `recommendation` and answer stub
  And its receipt records `factory.prd_grill.v1`, `answer_sheet_path`, the source hash, and no implementation authority

Scenario: reject invalid PRD input without artifacts
  Given a PRD with invalid UTF-8 bytes
  When PRD Grill reads the source
  Then it raises `PRD_ENCODING_INVALID` without an artifact

Scenario: preserve the implementation boundary
  Given a PRD with no unresolved decision questions
  When the caller confirms shared understanding
  Then the receipt records `PRD_GRILL_SHARED_UNDERSTANDING_CONFIRMED`
  And no product mission, deployment, publication, message, credential, or connector action occurs
```

## SHOULD — Technical/structural
- ADR references: existing Product Missions authority and source-binding policy.
- Data model: a source-bound receipt stored below `.factory/prd-grills/project-id`.
- API contract: `factory prd grill path/to/PRD.md --root workspace --mode quick|deep`
  with optional `--out`, `--project`, `--confirm`, `--force`, and `--json`.

## SHOULD NOT — Implementation details
- Do not call a model, execute an agent, read credentials, mutate the input
  PRD, infer answers, generate requirements, create a remote issue, or trigger
  an external effect.
- Do not ask a user for a fact that the local PRD analysis or allowlisted local
  repository metadata can supply.

## Decision logic (factory candidates)
This feature has no HSF business-decision candidate. Its question selection is
local deterministic controller behavior, fully constrained by the requirements
above, and all product decisions remain human-controlled.
