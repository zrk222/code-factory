# Spec: credential-proof-helper-consolidation-68
Status: draft | approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Consolidate the specifically mapped method-use and constructor-provider proof helpers into four already-existing host modules. Keep analysis behavior, helper names used by callers, cache invalidation, and test inventory unchanged while removing eleven redundant core Python module files.

### User roles
- Maintainer reviewing a bounded architecture reduction

### Requirements (EARS)
- The system shall retain the existing method-use audit hosts `method-use-hosts` named `credential_role_method_use_audit.py` and `credential_role_method_use_getter_audit.py`, and shall delete exactly the seven mapped method-use helper modules after moving their required definitions into those hosts.
- The system shall retain the existing constructor hosts `constructor-hosts` named `credential_role_constructor_provider.py` and `credential_role_constructor_provider_provenance.py`, and shall delete exactly the four mapped constructor helper modules after moving their required definitions into those hosts.
- The system shall return the same values for every existing acceptance fixture tagged `helper-return-equivalence` after only the mapped import retargets and explicitly reviewed duplicate-equivalent definition removal.
- The system shall emit the same pytest node identifier list tagged `same-node-id-list` before and after the consolidation; every existing test function, fixture, and assertion expression shall remain present.
- When a moved helper participates in freshness or cache validation, the retained host implementation shall remain bound by the `moved-helper-epoch-chain` of active code, defaults, closures, nested helper epochs, import inventory, source snapshot, and cache behavior.
- The system shall emit resolved module names tagged `approved-import-targets` pointing to retained hosts for every approved import and helper-inventory callsite; the worktree preservation verifier shall emit identical hashes for each unrelated dirty and untracked path.
- The system shall create zero Python compatibility modules tagged `no-compatibility-modules` and shall preserve the architecture caps at exactly 129 core modules and 460 tracked Python files.
- When the architecture health command measures exactly the eleven mapped tracked-file deletions and no other tracked path change, the architecture health command shall emit a report tagged `architecture-counts` listing 192 core modules, 593 tracked Python files, caps of 129 and 460, and a nonpassing cap status.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Method-use definitions remain available in existing hosts
  Given the approved nine-module method-use family and its listed callers
  When the seven helper modules are merged into the two retained audit hosts
  Then the existing method-use tests import the mapped helper names and produce the same collected node identifiers and assertion results

Scenario: Constructor-provider cache epochs cover merged helpers
  Given the approved six-module constructor family and the existing helper epoch tests
  When capture, provider-model, consumer, and type-effect definitions move into the two retained constructor hosts
  Then the existing cache and freshness tests detect the same helper, source, and import-map mutations

Scenario: Worktree scope remains bounded
  Given the hash-bound pre-edit candidate manifest and protected overlay
  When the consolidation patch is applied
  Then exactly eleven mapped old Python paths are deleted and every unrelated overlay file remains byte-identical

Scenario: Architecture count reduction is measured honestly
  Given unchanged architecture policy and caps
  When the architecture health command measures the candidate with only the mapped eleven deletions
  Then the report lists 192 core modules, 593 tracked Python files, caps of 129 and 460, and a failing cap status
```

## SHOULD — Technical/structural
- ADR references: `.factory/regression60/architecture-consolidation-map.md`
- Data model: no data model change; Python static-analysis helper functions and their existing index/cache epochs only
- API contract (OpenAPI path or interface): existing internal imports in the retained host modules and listed test/callsite imports

## SHOULD NOT — Implementation details
- Do not change analysis classifications, accepted/rejected cases, helper bodies, normalization, cache-key semantics, fixtures, or assertions.
- Do not create compatibility shims, new Python modules, or blanket architecture exemptions.
- Do not reclassify the architecture boundary or raise caps.
- Do not stage or commit shared worktree changes.

## Decision logic (factory candidates)
Each exact requirement tag maps to one verification obligation; these rows do not change code classifications. The accepted path set remains fixed by the hash-bound baseline manifest and the approved read-only map.
| # | if | then |
|---|----|------|
| 1 | `method-use-hosts` | verify retained method-use host imports |
| 2 | `constructor-hosts` | verify retained constructor host imports |
| 3 | `helper-return-equivalence` | compare existing fixture results |
| 4 | `same-node-id-list` | compare collected test node identifiers |
| 5 | `moved-helper-epoch-chain` | verify helper freshness and cache epoch coverage |
| 6 | `approved-import-targets` | resolve every mapped import target |
| 7 | `no-compatibility-modules` | verify no compatibility modules were created |
| 8 | `architecture-counts` | measure exact architecture counts and cap state |
