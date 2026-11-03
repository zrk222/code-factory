# Spec: native-database-context
Status: approved
SpecFactor-target: 0.75�2.5

## MUST � Functional core
### Description
Integrate source-bound database structure, migration operations and query dependencies into CF scan receipts, reusable by ForgeLine and SpecLine without executing project code or reading application rows.
### User roles
- Developers reviewing application data contracts and repairs.
### Requirements (EARS)
- The system shall extract tables, columns, constraints, indexes and query relationships from PostgreSQL or SQLite SQL ASTs and supported SQLAlchemy Python ASTs, verified by `database_structure_grounded`.
- If SQL or ORM structure is unresolved, a file changes, or a resource budget is exceeded, the system shall preserve the evidence gap and reject a complete database assessment, verified by `database_gaps_fail_closed`.
- The system shall hash source provenance and deterministic database facts separately from volatile telemetry, reject changed sources, and reuse only exact parser/dialect/content identities within 16 entries and 4000000 bytes, verified by `database_identity_current`.
- The system shall expose the same database map through existing scan receipts and context selection without issuing database writes or treating JEV output as schema authority, verified by `database_workflow_shared`.
- When `REQ_SOURCE_IDENTITY` evaluates captured source, the extractor shall store source path, SHA256, callable identity and bounded callsite chain, preserving the existing 64 selected modules, 128 source inventory, 65536 AST-source bytes and 1048576 source bytes caps.
- When `REQ_RESOURCE_FACTS` evaluates SQLite resource facts, the extractor shall store driver identity, database-value provenance and schema effects as exactly 3 independent categories; opaque guards shall not rebind caller-local resource identity but unknown close and schema effects remain unknown.
- When `REQ_UNKNOWN_BOUNDARY` evaluates unknown boundaries, the extractor shall emit explicit gaps for arbitrary public callers, unresolved imports, reflection, escapes, rebinding and recursion or context budget exhaustion, and shall not derive database COMPLETE from unresolved facts.
- When `REQ_CONTEXT_FLOW` evaluates finite callsite contexts, the extractor shall emit only source-hashed resource-bearing call contexts and reject imported ambiguity; closure over guard calls shall require their captured sources and existing context caps shall remain unchanged.
- When `REQ_SQL_CONSTRAINTS` evaluates finite SQL constraints, the extractor shall return bare PrimaryKey, ForeignKey and Unique facts, column CHECK references and SQLite INTEGER PRIMARY KEY AUTOINCREMENT facts; invalid types and references shall emit gaps.
- When `REQ_TRIGGER_STATEMENT` evaluates complete trigger statements, the extractor shall return BEFORE INSERT, UPDATE or DELETE triggers with optional WHEN EXISTS and one SELECT RAISE ABORT literal body; quoted semicolons and END tokens shall not split that statement and unsupported bodies shall emit gaps.
- When `REQ_TRIGGER_REFERENCES` evaluates trigger reference validation, the extractor shall reject invalid NEW and OLD event references and unknown target columns; WITHOUT ROWID tables reject implicit rowid and implicit rowid requires a native SQLite rowid table and explicit column shadowing shall take precedence.
- When `REQ_DIAGNOSTIC_CONSERVATION` evaluates security conservation, the extractor shall return all 6 existing synthetic credential diagnostics and source-context review boundaries without inferring CLEAN or release approval from database completeness.
- When `REQ_COMPATIBILITY` evaluates compatibility boundaries, the extractor shall return the existing public entry-point signatures and preserve module count, current caps and frozen N443 inputs; no dependency, install or policy change belongs to this feature.
- When `REQ_OBSERVED_SCHEMA` evaluates observed schema provenance, the extractor shall emit controlled-bootstrap SQL as observed context without asserting a shipped migration or universal initialized database; existing database status semantics shall remain unchanged.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: source-bound database understanding
  Given a SQLite or PostgreSQL schema and an application query
  When CF builds database context
  Then `database_structure_grounded` is true
  Then `database_gaps_fail_closed` is true
  Then `database_identity_current` is true
  Then `database_workflow_shared` is true
Scenario: REQ_SOURCE_IDENTITY
  Given `REQ_SOURCE_IDENTITY` and a captured callee changes bytes after its callsite context was recorded
  When the source hash is checked again
  Then the prior context is rejected and changed-source evidence remains unresolved
Scenario: REQ_RESOURCE_FACTS
  Given `REQ_RESOURCE_FACTS` and a resolved SQLite connect callee evaluates a dynamic path conversion or enters a transaction without an as target
  When resource identity and effects are inspected
  Then driver identity is retained separately from unknown path and schema effects
Scenario: REQ_UNKNOWN_BOUNDARY
  Given `REQ_UNKNOWN_BOUNDARY` and an arbitrary factory or external caller supplies a receiver
  When the receiver executes a query
  Then the unknown context remains visible and cannot supply a proven schema
Scenario: REQ_CONTEXT_FLOW
  Given `REQ_CONTEXT_FLOW` and two proven callsites pass different SQLite resources through the same parameter
  When the callable is analyzed
  Then each resource keeps its own schema and an unproven entry remains unresolved
Scenario: REQ_SQL_CONSTRAINTS
  Given `REQ_SQL_CONSTRAINTS` and a native SQLite table contains bare constraints and a CHECK or AUTOINCREMENT column
  When valid and invalid counterparts are parsed
  Then valid facts remain and invalid column references or non-INTEGER primary keys emit gaps
Scenario: REQ_TRIGGER_STATEMENT
  Given `REQ_TRIGGER_STATEMENT` and a trigger contains quoted END and semicolon text or an unsupported mutating body
  When the unchanged SQL statement is parsed
  Then quoted boundaries remain intact and the mutating counterpart remains unsupported
Scenario: REQ_TRIGGER_REFERENCES
  Given `REQ_TRIGGER_REFERENCES` and paired rowid and WITHOUT ROWID tables use NEW or OLD in different trigger events
  When target references are checked
  Then only event-compatible real columns and eligible implicit rowid are accepted
Scenario: REQ_DIAGNOSTIC_CONSERVATION
  Given `REQ_DIAGNOSTIC_CONSERVATION` and the full declared WMM candidate contains 6 synthetic credential findings
  When the final source-role audit is compared with its captured inputs
  Then all 6 raw findings remain and any context adjudication stays explicit
Scenario: REQ_COMPATIBILITY
  Given `REQ_COMPATIBILITY` and the proposed source diff and API signatures are compared with the existing baseline
  When compatibility and architecture checks run
  Then no module, cap, frozen input or public API change is accepted
Scenario: REQ_OBSERVED_SCHEMA
  Given `REQ_OBSERVED_SCHEMA` and the source-hashed schema comes from a disposable controlled bootstrap
  When the actual declared WMM projection is audited
  Then the receipt identifies observed context and unresolved receiver or effect facts remain gaps
```
## SHOULD � Technical/structural
- Lazy-load one SQL AST parser. Bound discovery to 256 SQL inputs, 1000000 bytes per input and 16000000 total retained bytes; cache at most 16 immutable serialized graph entries with a 4000000-byte total bound.
- Keep database inventory distinct from Python coverage; preserve fresh source checks and explicit dialect provenance.
- Data model: source-hashed callable contexts; separate resource, database-value and effect facts.
- API contract: preserve database_structure and current aliases in intent_quality.

## SHOULD NOT � Implementation details
- Do not execute ORM imports, migration files, SQL commands or production queries; do not include row data, connection credentials or SQL string literals in reports.
- Explicit migration ordering must cover every SQL path exactly once; bind the supplied order into cache and graph identity. Missing, duplicate or unknown paths remain incomplete. SQL/ORM declaration conflicts must remain visible rather than silently merged.
- No new implementation module, dependency, installation, cap increase, fixture renaming, snapshot rewriting or policy relaxation.
- No WMM product change or whole-workspace closure claim from a selected source set.

### Declared facts
- dialects: SQLite and PostgreSQL
- sql_input_limit: 256
- per_file_bytes: 1000000
- total_source_bytes: 16000000
- cache_entries: 16
- cache_bytes: 4000000

## SQLite refinement record
The SQLite requirements were consolidated here after implementation. Original requirements remain intact; fresh gates do not represent retroactive pre-edit approval.
