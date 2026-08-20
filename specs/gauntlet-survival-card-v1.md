# Spec: gauntlet-survival-card-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST — Functional core
### Description
Compile an inspectable, source-bound adversarial proof batch from declared
promises and human-written E2E argv pairs. A named human admits exactly one
local batch execution. The resulting Survival Card exposes every surviving,
hollow, blocked, and unproven promise; it can be checked offline and optionally
sealed with the existing Receipt v2 DSSE/Ed25519 path.

### User roles
- **Promise owner:** declares a plain-language promise and links its local sabotage cases.
- **Reviewer:** admits one exact proposal batch with a name, reason, and expiry.
- **Verifier:** reads the card or verifies its optional signature; never reruns commands through the read path.
- **MCP client:** reads local Gauntlet facts only.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- When `factory gauntlet plan` receives one source, the system shall emit `GAUNTLET_PROPOSAL_COMPILED` or `GAUNTLET_PROPOSAL_STALE` in `factory.gauntlet-proposal.v1` with one source SHA-256, one declared promise per source promise, one explicit risk taxonomy tag per case, and one current human-written `factory.e2e_proof_manifest.v1` SHA-256 per case.
- When a Gauntlet source declares a list of 1 through 12 continuity record IDs and every selected record has an RFC3339 `expires_at` where `expires_at > current_utc`, the system shall bind only independently promoted `factory.continuity.record.v1` metadata whose tenant, purpose, and scope equal the requested values through the read-only continuity API, emit `GAUNTLET_CONTINUITY_METADATA_BOUND`, and omit memory references, summaries, bodies, embeddings, and transcripts from the proposal and Survival Card.
- If at least 1 selected continuity record is unavailable, has `expires_at` at or before current UTC time, is unpromoted, or is outside the requested tenant, purpose, or scope, then the system shall emit `GAUNTLET_CONTINUITY_UNAVAILABLE` or `GAUNTLET_CONTINUITY_STALE`, mark the proposal stale, and shall not admit or execute its batch.
- When `factory gauntlet admit` receives one current compiled proposal receipt, one named reviewer, one rationale, one confirmation phrase, and one expiry of at most sixty minutes, the system shall emit `GAUNTLET_ADMISSION_SEALED` without executing a command.
- If `factory gauntlet run` receives zero current `GAUNTLET_ADMISSION_SEALED` receipts or one admission whose `expires_at` is at most the current UTC time and no more than sixty minutes after `issued_at`, then the system shall return `GAUNTLET_ADMISSION_REQUIRED` or `GAUNTLET_ADMISSION_EXPIRED` and shall not execute a command.
- When one admitted Gauntlet batch runs, the system shall execute only the current declared E2E argv pairs with the existing `shell=False` proof gate, classify `E2E_PROOF_PASS`, `E2E_POSITIVE_FAILED`, `E2E_POSITIVE_TIMEOUT`, `E2E_NEGATIVE_TIMEOUT`, and `E2E_ARTIFACT_MISSING`, and shall record one case outcome per declared case.
- If one declared negative command exits zero as `HOLLOW_E2E_TEST`, then the system shall emit `GAUNTLET_HOLLOW` and list that case and its promise as unproven on the Survival Card.
- When all declared positive commands exit zero, all declared negative commands exit non-zero, and all declared artifacts exist, the system shall emit `GAUNTLET_SURVIVED` or `GAUNTLET_BLOCKED` without claiming production readiness, security, coverage, performance, cost, token savings, quality, or a release decision.
- When `factory gauntlet card verify` receives one card, the system shall verify its canonical hash, its card views, and every embedded public E2E receipt offline; if a DSSE envelope and trust root are also supplied, the system shall verify that its Receipt v2 subject SHA-256 matches the card SHA-256.
- If one `factory.survival-card.v1` canonical hash, derived view, outcome summary, or embedded public E2E receipt does not match, then the system shall return `SURVIVAL_CARD_INVALID`.
- When Graph Ops or MCP reads one Survival Card, the system shall return `MCP_GAUNTLET_READ_ONLY` local facts and shall not run a Gauntlet, apply a repair, approve, merge, publish, deploy, sign, send a message, access credentials, or call a connector.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: An admitted batch survives declared sabotages
  Given `factory.gauntlet-proposal.v1`
  And one named unexpired `GAUNTLET_ADMISSION_SEALED` receipt
  And every declared E2E negative command exits non-zero
  When `factory gauntlet run` runs
  Then the system returns `GAUNTLET_SURVIVED`

Scenario: A proposal is compiled before admission
  Given one declared `GAUNTLET_PROPOSAL_COMPILED` source
  When `factory gauntlet admit` receives the compiled proposal
  Then the system returns `GAUNTLET_ADMISSION_SEALED`

Scenario: Verified context makes an intent binding precise without becoming authority
  Given one independently promoted current exact-scope continuity record
  And one Gauntlet source that declares that record ID
  When `factory gauntlet plan` runs
  Then the system returns `GAUNTLET_CONTINUITY_METADATA_BOUND`
  And the proposal omits the memory reference and summary

Scenario: A run preserves the existing shell boundary
  Given one admitted Gauntlet batch with `shell=False`
  When `factory gauntlet run` runs
  Then the system records one case outcome per declared case

Scenario: A hollow negative check stays visibly unproven
  Given one admitted Gauntlet batch
  And one declared negative command exits zero
  When `factory gauntlet run` runs
  Then the system returns `GAUNTLET_HOLLOW`
  And the Survival Card lists that promise as unproven

Scenario: An unadmitted batch cannot run
  Given `factory.gauntlet-proposal.v1`
  When `factory gauntlet run` runs without an admission receipt
  Then the system returns `GAUNTLET_ADMISSION_REQUIRED`

Scenario: A tampered card cannot verify
  Given `factory.survival-card.v1`
  And one changed outcome count
  When `factory gauntlet card verify` receives that Survival Card
  Then the system returns `SURVIVAL_CARD_INVALID`

Scenario: Read surfaces do not execute a Gauntlet
  Given one `MCP_GAUNTLET_READ_ONLY` Survival Card projection
  When Graph Ops reads the local projection
  Then the system returns `MCP_GAUNTLET_READ_ONLY`
```

## SHOULD — Technical/structural
- ADR references: `docs/GAUNTLET.md`, `docs/REALITY_CHECK.md`, and `docs/SIGNED_RECEIPTS.md`.
- Data model: immutable proposal, admission, card, SVG, Markdown, and optional DSSE files under `.factory/gauntlets/approval-gauntlet/`; optional Continuity bindings carry only redacted metadata and hashes.
- API contract: local CLI `factory gauntlet`, Graph Ops projection, and read-only MCP `factory.gauntlet_status`.

## SHOULD NOT — Implementation details
- Do not infer a promise, generate an argv pair from prose, invoke a model, silently admit a batch, or reuse an expired admission.
- Do not retrieve, copy, or treat Continuity content as test, run, approval, repair, or release authority.
- Do not call a card signed unless the provided DSSE envelope and trust root verify the exact card SHA-256.
- Do not treat a passing batch as a production, security, release, or quality certification.

## Decision logic (factory candidates)
<!-- Ordered business rules over extracted facts. specline handoff compiles
     these via HSF instead of letting agents improvise them. -->
| # | if | then |
| 1 | proposal source or E2E binding is stale | return `GAUNTLET_PROPOSAL_STALE` |
| 1a | selected Continuity metadata is unavailable or stale | return `GAUNTLET_CONTINUITY_UNAVAILABLE` or `GAUNTLET_CONTINUITY_STALE` |
| 2 | `GAUNTLET_ADMISSION_REQUIRED` | return `GAUNTLET_ADMISSION_REQUIRED` |
| 3 | `GAUNTLET_ADMISSION_EXPIRED` | return `GAUNTLET_ADMISSION_EXPIRED` |
| 4 | `HOLLOW_E2E_TEST` | emit `GAUNTLET_HOLLOW` |
| 5 | `E2E_POSITIVE_FAILED` or `E2E_POSITIVE_TIMEOUT` or `E2E_NEGATIVE_TIMEOUT` or `E2E_ARTIFACT_MISSING` | emit `GAUNTLET_BLOCKED` |
| 6 | `E2E_PROOF_PASS` for every declared case | emit `GAUNTLET_SURVIVED` |
|---|----|------|
