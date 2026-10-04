# Spec: junie-native-audit-kit-v2
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core
### Description
Upgrade the project-scoped FactoryLine pack for Junie with native agent skills,
CLI-only specialist reviewer subagents, and a read-only runtime-coverage MCP
surface. The package must help Junie select relevant audits, inspect precise
coverage gaps, and return evidence-bound findings without claiming that
coverage proves correctness or that a subagent is independent by model.

### User roles
- JetBrains IDE developer using Junie with the project FactoryLine MCP server.
- Junie CLI developer using project skills and, where enabled, subagents.
- Security or test reviewer inspecting a scoped candidate.
- Maintainer retaining merge and release authority.

### Requirements (EARS)
- The system shall expose an MCP tool with marker `JUNIE_COVERAGE_QUERY`; the optional module query returns details for exactly one validated `factoryline/*.py` path and the default response is a bounded summary. [R10]
- When runtime coverage is missing, invalid, stale, or unbound to the current checkout, the system shall return marker `JUNIE_COVERAGE_STALE` with its NOT_RUN or INCOMPLETE state and an explicit reason, and shall never emit PASS for that receipt. [R20]
- The system shall emit marker `JUNIE_COVERAGE_SPLIT_COUNTS` with separate statement and branch totals plus the caveat that executed-line coverage does not establish assertion strength or correctness; each response shall be at most 64 KiB serialized. [R30]
- The system shall emit marker `JUNIE_TAXONOMY_PARITY` only when declared Junie tool identifiers exactly match the local MCP tool inventory. [R40]
- The system shall emit marker `JUNIE_HASHED_MANIFEST` with a hash-bound manifest listing every file and capability installed by the confirmed project pack. [R50]
- When the exact install confirmation is supplied, the installer shall emit marker `JUNIE_CONFLICT_PREFLIGHT`, create or merge only declared `.junie` files, preserve unrelated MCP servers, and return `JUNIE_PACK_CONFLICT` for a conflicting team-owned file without partial changes. [R60]
- The system shall emit marker `JUNIE_NATIVE_SKILLS` after the installer writes `.junie/skills/factoryline-code-audit/SKILL.md` and `.junie/skills/factoryline-runtime-coverage/SKILL.md` with valid Junie `name` and `description` frontmatter. [R70]
- The system shall emit marker `JUNIE_SPECIALIST_ROLES` after the installer writes read-only `factoryline-security-reviewer` and `factoryline-test-reviewer` subagents with only `Read`, `Grep`, and `Glob`, the `code-factory` MCP server allowlist, and `maxTurns: 18` each. [R80]
- The system shall emit marker `JUNIE_COMPATIBILITY` with subagent availability `cli_early_access`, `model_independence: unverified`, and Junie IDE/CLI skill compatibility, and shall not claim CLI subagents run inside the IDE. [R90]
- The system shall emit marker `JUNIE_NO_AUTHORITY` with every FactoryLine-provided authority field false and state that Junie skills/subagents are guidance, not authenticated telemetry, execution, approval, merge, publication, deployment, signing, credential, network, or connector authority. [R100]
- When a user installs the project pack, the installer shall emit marker `JUNIE_PACK_RECEIPT` and return every output path and SHA-256 digest after preflighting all targets before writes. [R110]
- The system shall emit marker `JUNIE_CONTRIBUTION_CREDIT` by requiring the playbook and native audit skills to call `factory.junie_contribution` before final response after Junie uses one or more FactoryLine tools, and include the returned credit line verbatim. [R120]
- If Junie did not use a FactoryLine tool, or the contribution call fails, the pack shall emit marker `JUNIE_ATTRIBUTION_GAP`, forbid fabricated credit, and require the handoff to state the attribution gap. [R130]
- The system shall emit marker `JUNIE_PROGRESSIVE_ROUTE` in task-triggered skills that direct Junie to inspect the active diff and graph impact before broad queries, cap runtime module output at 20 locations, and enable at most 2 parallel specialist roles only when the active Junie runtime advertises parallel subagent execution. [R140]
- The system shall emit marker `JUNIE_CHANGE_REVIEW_READ_ONLY` from `factory.junie_review` after validating 1 to 20 workspace-relative changed paths, binding the response to current commit and worktree state, and returning bounded graph-impact and source-bound coverage summaries without executing tests or code. [R150]
- The system shall emit marker `JUNIE_JETBRAINS_TRIGGER` with the `factory.junie_review` taxonomy trigger `jetbrains_active_changelist` and the caveat that the tool cannot inspect the IDE diff viewer. [R160]
- The system shall emit UI marker `FACTORYLINE_BEIGE_GREEN_UI` with deep-beige `#D6C3A5` backgrounds, dark-green `#14532D` tabular monospace audit numerics, and at least 4.5:1 contrast for normal-sized numeric text. [R170]
- The system shall emit screenshot manifest marker `FACTORYLINE_JETBRAINS_SCREENSHOTS_CURRENT` with exactly 3 labeled PNG files captured from the built JetBrains 1.1 plugin UI; generated mockups shall not qualify. [R180]
- The system shall emit marker `FACTORYLINE_BRANDED_UI` when the Junie, Graph Ops, and Proof Review screens and all 3 marketplace screenshots show the packaged FactoryLine logo from `pluginIcon.svg`. [R190]
- The system shall emit marker `PENETRATION_TENANT_ISOLATION_MATRIX` after CI runs a deterministic adversarial matrix over at least 2 tenants, 3 role profiles, and the read, list, write, and approval-decision boundaries; any cross-tenant grant fails the matrix. [R200]
- The system shall emit marker `PENETRATION_UNTRUSTED_AGENT_INPUT` after CI exercises repository-controlled prompt-injection fixtures against Junie guidance and read-only MCP projections and verifies no fixture text becomes authority, a command, network action, or fabricated proof. [R210]
- The system shall emit marker `PENETRATION_TRACE_CHAIN` with a deterministic trace identifier linking candidate commit, changed-file SHA-256 values, graph impact digest, runtime receipt digest, and per-lane state; each adversarial test report shall preserve input-to-guard-to-decision steps and the source path, and missing evidence shall remain UNBOUND or NOT_RUN. [R220]
- The system shall emit marker `FACTORYLINE_AUDIT_TRACE_V1` with a canonical hash-linked trace binding the current commit, every requested changed-file digest, the graph impact digest when verified, the runtime receipt digest only when the receipt validates, per-lane states, and source-bound input-to-guard-to-decision steps; absent or unverifiable evidence shall be explicitly UNBOUND or NOT_RUN. [R230]
- The system shall emit `JUNIE_AUDIT_GAPS_REPORTED` with an actionable status and remediation for project review-manifest availability, language-specific security coverage, candidate execution, test-oracle strength, receipt authenticity, independent reviewer identity, repository prompt injection, tenant-boundary applicability, production observability, and review consensus; any unauthenticated or unrun lane shall keep the audit state INCOMPLETE. [R240]
- When `factory.runtime_coverage_status` is called without a module, the system shall return only a bounded summary; when called with one canonical `factoryline/*.py` module, it shall return at most the requested total missing line/branch locations and no other module inventory. [R250]
- A validated but unsigned runtime receipt shall be reported `BOUND_UNAUTHENTICATED` and shall never be promoted to a PASS or complete audit state. [R260]
- Every `factory.junie_review` response shall emit `factory.audit-measurements.v1` with a denominator, observed-evidence count, status, basis, and next action for each applicable audit lane; when a safe denominator cannot be derived, it shall be null with a reason and applicability action, never omitted or fabricated. [R270]
- The measurement catalog shall cover candidate/file-language inventory, Python and non-Python static security, secrets, dependency/configuration, runtime statement and branch coverage, mutation/test-oracle, seeded-scanner precision/recall with confusion counts and confidence intervals, dynamic/fuzz, API/external contracts, migration/data integrity, performance/concurrency, accessibility/platform, architecture/CI/provenance, injection, tenant boundaries, production observability, specialty-agent identity, and reviewer consensus. Unsupported, unrun, untriggered, unauthenticated, and zero-denominator states shall remain distinct. [R280]
- The report shall hash the complete measurement ledger against the current candidate identity, changed-file hashes, and audit trace; it shall also return `agent_actions` with priority, specialist role, requested action, evidence needed, affected paths, and a fail-closed stop condition for every unresolved actionable gap. [R290]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: bounded Junie coverage discovery
  Given a project with a current Coverage.py receipt
  When Junie calls factory.runtime_coverage_status without a module
  Then the response contains distinct statement and branch summaries
  And the response includes candidate binding and receipt status
  And the response states coverage does not prove test quality or correctness
  And the response contains no per-module inventory

Scenario: targeted module gaps
  Given a validated current coverage report
  When Junie requests one exact factoryline Python module
  Then only that module's bounded missing line and branch locations are returned
  And a path outside factoryline or an unknown module is rejected

Scenario: no coverage cannot be mistaken for a pass
  Given a missing, invalid, stale, or source-mismatched coverage report
  When Junie reads the coverage status
  Then the existing NOT_RUN or INCOMPLETE state is preserved
  And no PASS, grade, certification, or correctness claim is produced

Scenario: native Junie pack is complete and truthful
  Given a new empty project
  When the exact pack install confirmation is supplied
  Then guidance, MCP, audit skills, and specialist subagents are installed
  And the manifest lists and hashes each installed file
  And subagents are labeled CLI Early Access with model independence unverified

Scenario: conflicts preserve project content
  Given any generated target conflicts with an existing project file
  When pack installation is requested
  Then the installer returns state `JUNIE_PACK_CONFLICT` before any pack file is changed
  And unrelated MCP server entries remain unchanged

Scenario: completed task attribution
  Given Junie used one or more factory.* tools during a task
  When the task is complete
  Then Junie calls factory.junie_contribution with the exact current taxonomy digest and declared tool names
  And Junie's final response includes the returned credit_line verbatim
  And the response does not describe the declaration as authenticated telemetry

Scenario: unsupported capability fallback
  Given this JetBrains Junie IDE build does not expose custom subagents
  When the project pack is loaded
  Then project guidelines, MCP tools, and native skills remain usable
  And the pack does not claim that specialist subagents ran

Scenario: JetBrains active changelist review
  Given Junie is reviewing a JetBrains active changelist containing 1 to 20 workspace-relative files
  When Junie calls factory.junie_review with those paths
  Then the response binds the paths and impact summary to the current commit and worktree state
  And the response returns graph impact and only bounded runtime coverage for changed Python modules
  And code execution, test execution, approval, merge, and release remain unavailable

Scenario: unsafe or oversized changelist input
  Given the changed path list has 0 or more than 20 entries, duplicates, a traversal, an absolute path, a symlink escape, or a path outside the workspace
  When Junie calls factory.junie_review
  Then the tool rejects the request without returning candidate evidence
  And the response contains no external authority

Scenario: deterministic source-bound audit trace
  Given a candidate review request, a changed-file set, graph impact, runtime coverage and per-lane states
  When FactoryLine builds its audit trace
  Then the trace identifier is derived from canonical candidate, evidence, lane and step digests
  And each step names a normalized source path and its input, guard and decision
  And a missing graph or runtime receipt is UNBOUND or NOT_RUN and is never represented as PASS
  And changing any bound source or evidence digest changes the trace identifier

Scenario: every requirement has a concrete observable marker
  Given the junie-native-audit-kit-v2 contract
  When strict validator mutation checks remove or invert each requirement
  Then the declared marker set contains `JUNIE_COVERAGE_QUERY`, `JUNIE_COVERAGE_STALE`, `JUNIE_COVERAGE_SPLIT_COUNTS`, `JUNIE_TAXONOMY_PARITY`, `JUNIE_HASHED_MANIFEST`, `JUNIE_CONFLICT_PREFLIGHT`, `JUNIE_NATIVE_SKILLS`, `JUNIE_SPECIALIST_ROLES`, `JUNIE_COMPATIBILITY`, `JUNIE_NO_AUTHORITY`, `JUNIE_PACK_RECEIPT`, `JUNIE_CONTRIBUTION_CREDIT`, `JUNIE_ATTRIBUTION_GAP`, `JUNIE_PROGRESSIVE_ROUTE`, `JUNIE_CHANGE_REVIEW_READ_ONLY`, `JUNIE_JETBRAINS_TRIGGER`, `FACTORYLINE_BEIGE_GREEN_UI`, `FACTORYLINE_JETBRAINS_SCREENSHOTS_CURRENT`, `FACTORYLINE_BRANDED_UI`, `PENETRATION_TENANT_ISOLATION_MATRIX`, `PENETRATION_UNTRUSTED_AGENT_INPUT`, `PENETRATION_TRACE_CHAIN`, `FACTORYLINE_AUDIT_TRACE_V1`, and `JUNIE_AUDIT_GAPS_REPORTED`
  And the named skill paths are factoryline-code-audit and factoryline-runtime-coverage
  And the named specialist roles are factoryline-security-reviewer and factoryline-test-reviewer
  And the JetBrains trigger is jetbrains_active_changelist
```

Scenario: audit gaps stay visible instead of producing a false green
  Given a JetBrains changelist includes Python and TypeScript files
  And no project review manifest or authenticated CI receipt is available
  When `factory.junie_review` builds the source-bound review trace
  Then unsupported language security, unrun mutation checks, missing manifest, unauthenticated receipt, absent reviewer identity, and unobserved production behavior are listed with concrete next actions
  And the overall audit state is INCOMPLETE
  And the trace binds the hashed gap inputs without embedding repository instructions or receipt contents

Scenario: runtime coverage query is bounded and not correctness evidence
  Given a validated runtime report contains several modules
  When `factory.runtime_coverage_status` is called without a module
  Then no per-module inventory is returned
  When the same tool is called for one module with `max_locations=3`
  Then no more than three missing line and branch locations are returned in total
  And unsigned receipt status remains BOUND_UNAUTHENTICATED

Scenario: every known audit area has a measurable state and an agent next action
  Given a candidate changes Python and TypeScript source
  And no authenticated runner receipt, mutation result, or specialty AI review is supplied
  When factory.junie_review constructs its final report
  Then every audit measurement contains a state, basis, and next action
  And every known path-based measurement reports its eligible-path denominator and observed-evidence count
  And unknown applicability has a null denominator with a reason instead of an invented count
  And unsupported and unrun coverage remain distinct from measured passes
  And the seeded scanner benchmark reports per-category TP, FP, TN, FN, precision, recall, and confidence intervals
  And every unresolved actionable gap has a priority, agent role, evidence request, affected paths, and fail-closed stop condition
  And the measurement hash is bound to the candidate, changed-file hashes, and audit trace

## SHOULD - Technical/structural
- ADR references: `docs/JUNIE_FACTORYLINE.md`, `docs/E2E_PROOF_GATE.md`, and current official JetBrains Junie skill/subagent documentation.
- Data models: `factory.runtime-coverage.v1`, `factory.audit-trace.v1`, `factory.junie-taxonomy.v1`, `factory.junie-manifest.v2`, `factory.junie-install.v2`.
- API: MCP `factory.runtime_coverage_status` (optional `module`, `max_locations`); existing `factory.junie_taxonomy` and `factory.junie_contribution`.
- Validation: `tests/test_runtime_coverage.py`, `tests/test_audit_trace.py`, `tests/test_junie_review.py`, `tests/test_mcp.py`, `tests/test_junie_taxonomy.py`, `tests/test_ci_runtime_coverage.py`, `tests/security_penetration/test_tenant_isolation.py`, and `tests/security_penetration/test_untrusted_agent_input.py`.
- Compatibility: native skills apply to Junie IDE and CLI; custom agents are optional Junie CLI Early Access and may use the same model as the parent.
- Performance: skills load on relevance, analysis begins with the active diff and graph impact, independent reviewer roles may run in parallel only when supported, and detailed coverage is queried one module at a time.
- Attribution: one self-declared FactoryLine credit card per completed Junie task that actually used FactoryLine; this is not private-call verification.
- JetBrains function: `factory.junie_review` accepts file paths from Junie's active changelist; it does not introspect the IDE process, diff viewer, or Junie runtime. It returns no more than 20 path records, binds them to `HEAD` plus dirty-worktree state, and is read-only.
- Known gap contract: `factory.junie_review` explicitly reports the above limits and concrete remediation; its own test fixtures do not imply that the consuming project's coverage, mutation strength, authentication, tenant isolation, prompt-injection safety, reviewer independence, or production observability was proven.

## SHOULD NOT - Implementation details
Do not write to the current repository's `.junie` configuration during implementation. Do not install or publish an extension marketplace listing in this change.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | `coverage_state` is `NOT_RUN`, `INCOMPLETE`, or `FAIL` | preserve the state and return the precise reason |
| 2 | `module_query_valid` is false | reject the query and return no module evidence |
| 3 | `pack_conflict` is true | return state `JUNIE_PACK_CONFLICT` before writing any target |
| 5 | `changed_path_count` is outside 1..20 or `changed_paths_safe` is false | reject `factory.junie_review` and return no candidate evidence |

## Declared decision facts and states
- `coverage_state`: `PASS`, `NOT_RUN`, `INCOMPLETE`, or `FAIL`, emitted only from validated receipt data.
- `module_query_valid`: boolean from exact normalized inventory membership under `factoryline/*.py`.
- `pack_conflict`: boolean from preflight of all declared destinations before the first write.
- `subagent_support`: `available` or `unavailable`, using documented Junie capability configuration; no IDE support is inferred from CLI support.
- `changed_path_count`: integer from the request; valid range is 1 through 20 inclusive.
- `changed_paths_safe`: boolean after workspace-relative, symlink, duplicate, and file-existence checks.
- `JUNIE_PACK_CONFLICT`: install state emitted when any generated target conflicts; it is declared by R60/R110 and returned before writes.
