# Spec: junie-factoryline-taxonomy-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Give a JetBrains Junie user one complete, progressive FactoryLine taxonomy.
The taxonomy is exposed as a read-only MCP discovery tool and as a
project-scoped Junie pack. The pack consists only of `.junie/AGENTS.md` and a
secret-free `.junie/mcp/mcp.json` entry after exact local confirmation. It
guides a coding agent to request intent, scope, evidence, and a human handoff
in that order; it neither starts Junie nor grants FactoryLine source, provider,
approval, merge, publish, deploy, signing, credential, network, or connector
authority.

### User roles
- JetBrains developer using Junie on a local project
- Human reviewer retaining the release decision
- Team lead who needs the same audit vocabulary across agents

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- The system shall emit `JUNIE_FACTORYLINE_TAXONOMY_READY` with 58 distinct MCP tool identifiers assigned to exactly seven ordered stages. [R10]
- When a client calls `factory.junie_taxonomy`, the system shall emit every external-effect authority field as `false`. [R20]
- The system shall emit an install confirmation rule containing `INSTALL Junie FactoryLine Pack`. [R25]
- When `confirmation` equals `INSTALL Junie FactoryLine Pack`, the system shall emit `JUNIE_FACTORYLINE_PACK_INSTALLED` after writing only `.junie/AGENTS.md` and `.junie/mcp/mcp.json` with SHA-256 fields. [R30]
- If an existing `.junie/AGENTS.md` or `code-factory` MCP entry differs, the system shall emit `JUNIE_PACK_CONFLICT` and preserve both project files. [R40]
- While the system renders `.junie/AGENTS.md`, the system shall emit intent and scope review, no scope expansion, no oracle weakening, and exact changed-path, test, evidence, failure, and unknown handoff rules. [R50]
- Where a tool belongs to AppForge, SaaS, enterprise, or release delivery, the system shall emit `default=false` for the containing stage. [R60]
- When Junie declares use of FactoryLine, the system shall emit `JUNIE_FACTORYLINE_CONTRIBUTION_DECLARED` only after matching the current taxonomy, validating the exact named FactoryLine tools, and hashing any cited workspace-local files; the system shall explicitly state that it cannot authenticate Junie or prove private tool calls. [R70]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: local taxonomy discovery
  Given a workspace directory
  When a client calls factory.junie_taxonomy
  Then the system emits JUNIE_FACTORYLINE_TAXONOMY_READY
  And every external-effect authority field is false

Scenario: exact confirmation pack write
  Given confirmation is exact
  When the system processes confirmation
  Then the system emits JUNIE_FACTORYLINE_PACK_INSTALLED
  And the system writes only project guidance and project MCP configuration

Scenario: project conflict
  Given a project guidance file differs
  When the system processes confirmation
  Then the system emits JUNIE_PACK_CONFLICT
  And the system preserves project files

Scenario: evidence-bound Junie acknowledgement
  Given Junie supplies its current taxonomy digest, exact FactoryLine tool names, and local evidence paths
  When a client calls factory.junie_contribution
  Then the system emits JUNIE_FACTORYLINE_CONTRIBUTION_DECLARED
  And the system returns a clearly bounded FactoryLine credit line
```

## SHOULD — Technical/structural
- ADR references: `docs/REPAIR_SANDBOX.md`, `docs/E2E_PROOF_GATE.md`
- Data model: `factory.junie-taxonomy.v1`, `factory.junie-install.v1`,
  `factory.junie-factoryline-contribution.v1`
- API contract: `factory junie taxonomy|install|contribution`; MCP
  `factory.junie_taxonomy`, `factory.junie_contribution`
- Validation: `tests/test_junie_taxonomy.py`, `tests/test_mcp.py`, and
  `editors/intellij/src/test/kotlin/app/factoryline/intellij/FactoryLineCoreTest.kt`

## SHOULD NOT — Implementation details
<!-- Leave the "how" to the plan/tasks unless it is a systemic invariant -->

## Decision logic (factory candidates)
<!-- Ordered business rules over extracted facts. specline handoff compiles
     these via HSF instead of letting agents improvise them. -->
| # | if | then |
|---|----|------|
