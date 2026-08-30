# Spec: jetbrains-proof-handshake-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Join a human-sealed JetBrains Change List, a Junie/Copilot-compatible proof
mission, Qodana or SonarQube SARIF, and an optional non-hollow E2E receipt into
one local, hash-bound, supervised review decision. The bridge uses documented
file and MCP interfaces only and never starts or controls an agent or analyzer.

### User roles
- JetBrains developer using Junie, GitHub Copilot, or another coding agent
- Team reviewer using Qodana, SonarQube, and FactoryLine

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- The system shall reject a malformed or tampered scope with `SCOPE_REJECTED` before producing a mission or handshake.
- When a mission is requested, the system shall return `MISSION_SCOPE_BOUND` with exact sealed paths, behavioral promise, negative case, no-test-weakening rule, and required return facts.
- When Qodana or SonarQube SARIF 2.1.0 is supplied, the system shall return `ANALYSIS_BYTES_BOUND` after binding exact bytes, provider identity, counts, and integer thresholds without invoking an analyzer.
- If automatic provider detection is ambiguous or unrecognized, the system shall reject the report with `ANALYSIS_PROVIDER_REJECTED`.
- If the requested provider disagrees with the SARIF tool driver, the system shall reject the report with `ANALYSIS_PROVIDER_MISMATCH`.
- When returned changed paths exceed the sealed Change List, the system shall return `SCOPE_ESCAPE_BLOCKED`.
- If an E2E receipt is absent, stale, malformed, hollow, or non-passing, the system shall return `E2E_NOT_READY` instead of ready_for_human_review.
- If analyzer execution success is unobserved or intent is uncontracted, the system shall return `HANDSHAKE_REVIEW_REQUIRED` and never infer green.
- The system shall expose `MCP_HANDSHAKE_READ_ONLY` mission and handshake tools over stdio MCP and local WebMCP.
- The system shall return `MCP_INSTALL_CONFLICT` rather than overwrite a conflicting Junie or GitHub Copilot project entry.
- The system shall render `JETBRAINS_SUPERVISED_CONTROLS` for mission copy, Change List review, analyzer/E2E selection, and local Graph Ops without contacting a provider.
- The system shall render `PUBLIC_AGENT_ANALYZER_PROMISE` with the exact approved public sentence.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: a Junie change satisfies all supplied gates
  Given a hash-valid repair scope, matching returned paths, an intact ready Intent Ledger, a successful Qodana or SonarQube SARIF report within zero-new thresholds, and an e2e_state of passing
  When the handshake is evaluated
  Then the result is ready_for_human_review and still requires a human decision

Scenario: a green-looking agent run escapes scope
  Given a hash-valid repair scope and a returned path outside that scope
  When the handshake is evaluated
  Then it is blocked before analyzer or E2E success can make it green

Scenario: an agent weakens the negative test
  Given an analyzer-clean report and an e2e_state of hollow
  When the handshake is evaluated
  Then the result is blocked as hollow_e2e
```

## SHOULD — Technical/structural
- ADR references: `docs/REPAIR_SANDBOX.md`, `docs/E2E_PROOF_GATE.md`
- Data model: `factory.analysis-evidence.v1`, `factory.jetbrains-proof-handshake.v1`, `factory.agent-proof-mission.v1`
- API contract: `factory jetbrains mission|handshake`; MCP tools `factory.agent_proof_mission` and `factory.jetbrains_handshake`

## SHOULD NOT — Implementation details
<!-- Leave the "how" to the plan/tasks unless it is a systemic invariant -->

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | `SCOPE_REJECTED` is absent | block release |
| 2 | `MISSION_SCOPE_BOUND` is absent | block release |
| 3 | `ANALYSIS_BYTES_BOUND` is absent | block release |
| 4 | `ANALYSIS_PROVIDER_REJECTED` is absent | block release |
| 5 | `ANALYSIS_PROVIDER_MISMATCH` is absent | block release |
| 6 | `SCOPE_ESCAPE_BLOCKED` is absent | block release |
| 7 | `E2E_NOT_READY` is absent | block release |
| 8 | `HANDSHAKE_REVIEW_REQUIRED` is absent | block release |
| 9 | `MCP_HANDSHAKE_READ_ONLY` is absent | block release |
| 10 | `MCP_INSTALL_CONFLICT` is absent | block release |
| 11 | `JETBRAINS_SUPERVISED_CONTROLS` is absent | block release |
| 12 | `PUBLIC_AGENT_ANALYZER_PROMISE` is absent | block release |
