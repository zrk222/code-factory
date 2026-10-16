# Spec: invocation-import-reuse
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Resolve each local import once within a cold scan when both consumers have identical canonical-to-lexical source inventories, while preserving source-bound findings and drift rejection.
### User roles
- Developers scanning local source trees.
### Requirements (EARS)
- When inventories match, the system shall reuse immutable invocation-local import maps, verified by `matching_inventory_reused`.
- If inventories differ or capture exceeds 4096 aliases or 1048576 string characters, the system shall discard every captured map and resolve all project imports afresh, verified by `fallback_preserved`.
- The system shall preserve scan contexts, evidence edges and final source freshness checks across cold, warm and changed-input scans, verified by `scan_parity_preserved`.
### Acceptance criteria (Gherkin)
```gherkin
Scenario: bounded local reuse
  Given 4096 aliases and 1048576 string characters as capture limits
  When a cold scan binds local project contracts
  Then `matching_inventory_reused` is true
  Then `fallback_preserved` is true
  Then `scan_parity_preserved` is true
```
## SHOULD — Technical/structural
- Use existing modules and cache identities; add no persistent cache, service or public command.
## SHOULD NOT — Implementation details
- Do not reuse maps across invocations or omit independent source verification.
### Declared facts
- alias_limit: 4096
- character_limit: 1048576
