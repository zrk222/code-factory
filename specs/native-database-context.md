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
### Acceptance criteria (Gherkin)
```gherkin
Scenario: source-bound database understanding
  Given a SQLite or PostgreSQL schema and an application query
  When CF builds database context
  Then `database_structure_grounded` is true
  Then `database_gaps_fail_closed` is true
  Then `database_identity_current` is true
  Then `database_workflow_shared` is true
```
## SHOULD � Technical/structural
- Lazy-load one SQL AST parser. Bound discovery to 256 SQL inputs, 1000000 bytes per input and 16000000 total retained bytes; cache at most 16 immutable serialized graph entries with a 4000000-byte total bound.
- Keep database inventory distinct from Python coverage; preserve fresh source checks and explicit dialect provenance.
## SHOULD NOT � Implementation details
- Do not execute ORM imports, migration files, SQL commands or production queries; do not include row data, connection credentials or SQL string literals in reports.
- Explicit migration ordering must cover every SQL path exactly once; bind the supplied order into cache and graph identity. Missing, duplicate or unknown paths remain incomplete. SQL/ORM declaration conflicts must remain visible rather than silently merged.
### Declared facts
- dialects: SQLite and PostgreSQL
- sql_input_limit: 256
- per_file_bytes: 1000000
- total_source_bytes: 16000000
- cache_entries: 16
- cache_bytes: 4000000
