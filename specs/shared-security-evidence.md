# Spec: shared-security-evidence
Status: approved

## MUST — Functional core
### Description
Consolidate captured source, structural value and effect facts in existing scanner modules. Owner authorization: implement Astra368 into CF and the active goal. Approval records owner-delegated implementation review, not independent human validation.
### User roles
- Repository auditor: receives source-bound findings and explicit unknown premises.
### Requirements (EARS)
- The system shall record `SourceSnapshotIndex` facts and retain 1 source generation through native scanning and role classification, with at most 2000 files and 32 MB total and separate verifier reconstruction.
- The system shall record `IdentityEffectSummary` facts and retain selected return values and argument/call effects under exact captured bindings; unsupported paths shall remain unknown.
- The system shall record `_Value` facts and preserve selected container and field origins, scalar shape, and known may-origins when another premise is unknown.
- When assignments execute, the system shall store `_security_flow_source_assignment` structural values and transfer structural values without erasing origin steps; legacy flags shall be derived projections.
- The system shall record `security_helper_return_value` facts and supply shared result facts to at least two native families, shell/OS and pickle, before credential consumers migrate.
- The system shall record `captured_value_use_closure` facts and reject negative admission when relevant uses escape, rebind, or lack source-owned consumer registration.
- The system shall record `ClassChainMemo` facts and invalidate summaries when source, helper, binding, provider, budget, frontend or configuration identity changes.
- When an admitted producer model exists, the system shall return `_pickle_role_inventory` facts and reuse captured trees with zero producer reparses; verifier recomputation shall remain independent.
- The system shall reject `architecture-policy.json` constraint violations and remain at most 464 Python files and 133 core modules, with unchanged line and C901 ceilings and zero new engine modules.
- The system shall emit `Wilson95` measurements and distinguish exposed replays from a preregistered fresh cohort of at least 30 decided alerts and at least 80 percent actionable precision; unclear labels and all six known TP retention checks shall remain visible.
### Acceptance criteria (Gherkin)
```gherkin
Scenario: `SourceSnapshotIndex` producer lifetime
  Given captured bytes and an independent verifier
  When `SourceSnapshotIndex` supplies native scanning and role classification
  Then 1 source generation of at most 2000 files and 32 MB remains available through both consumers
Scenario: `IdentityEffectSummary` result and effects
  Given exact captured actual and formal bindings
  When `IdentityEffectSummary` evaluates a constant return and an effectful argument
  Then result lineage excludes the argument and call effects remain recorded
Scenario: `_Value` selected origins
  Given a container with a tainted sibling and an unknown sibling
  When `_Value` selects one literal key
  Then selected origins remain distinct and known may-origins survive unknown premises
Scenario: `_security_flow_source_assignment` continuity
  Given an input origin followed by assignment and a helper call
  When `_security_flow_source_assignment` transfers a value
  Then structural origins and source steps remain available after assignment
Scenario: `security_helper_return_value` native families
  Given shell/OS and pickle native call sites
  When `security_helper_return_value` supplies selected result facts
  Then at least two native families consume regenerated facts
Scenario: `captured_value_use_closure` incomplete uses
  Given an escaped or rebound relevant use
  When `captured_value_use_closure` evaluates negative admission
  Then admission remains unknown and raw diagnostics remain visible
Scenario: `ClassChainMemo` generation invalidation
  Given a cached source-bound summary
  When source or configuration or provider identity changes
  Then `ClassChainMemo` rejects the prior generation
Scenario: `_pickle_role_inventory` producer reuse
  Given an admitted source model and independent verifier reconstruction
  When `_pickle_role_inventory` reads captured trees
  Then producer reparses equal zero and verifier reconstruction remains independent
Scenario: `architecture-policy.json` budgets
  Given changes inside existing scanner modules
  When `architecture-policy.json` checks execute
  Then Python files remain at most 464 and core modules at most 133 with zero new engine modules
Scenario: `Wilson95` completion boundary
  Given a preregistered fresh cohort
  When `Wilson95` results are reported
  Then at least 30 decided alerts and at least 80 percent actionable precision are required with unclear labels and all six TP checks visible
```
## SHOULD — Technical/structural
- Cohort startup workers use `timeout = 90` seconds and `max_workers = 2`; startup readiness never guarantees completion of subsequent analysis. Every failed or stale startup check prevents launch.
- Source completeness and test-collection authority are separate premises. UNKNOWN pytest collection must not erase hash-bound source/value-origin facts used by collection-independent shell, local-worker and literal-program consumers. Test/fixture-dependent projections still require known collection; ordinary input/sink findings, original severity, UNKNOWN collection and INCOMPLETE status remain visible. Producer and independent verifier must reconstruct the same partition.
- An explicit security-only profile may continue bounded security analysis when custom pytest hooks or plugin declarations make test collection unknown. The strict default still rejects those inputs. The profile must bind selected configuration and relevant hook/plugin source hashes, record UNKNOWN with empty file/function/class collection settings, suppress test-oracle and fixture-role credit, and preserve ordinary security findings and source bytes. Malformed, unreadable or oversized configuration remains an error. UNKNOWN collection must survive native sealing, cache, policy, serialization and persisted read-back as INCOMPLETE with no clean or release credit; source/config/hook drift must invalidate the receipt. A profile change requires a newly frozen evaluation; incomplete Study382 is retained without a score claim.
- Existing source capture, structural values and finite helper flow are the implementation surface.
- Delete replaced producer traversals after parity; verifier parsing remains independent.
- Keep Python, PHP, runtime and oracle frontend identities separate; JEV remains secondary.
## Decision logic (factory candidates)
No new ordered admission policy. Existing family-specific proof obligations remain authoritative.

## Authorized parameters
timeout = 90
max_workers = 2
