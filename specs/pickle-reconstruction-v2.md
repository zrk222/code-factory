# Spec: pickle-reconstruction-v2
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Model conditional reconstruction of an already initialized provider class. Separate historical definition-time effects from effects that deserialization actually invokes. Bind cached global identity, constructor/state semantics and byte origin independently; preserve source-closed and v1 behavior.

### Requirements (EARS)
- When `PICKLE_V2_SELECTED` requests trusted-dependencies-v2, the system shall validate 1–32 canonical provider contracts for scanner-owned builtin-exception-record-v1 or builtin-exception-record-v2 models, reject ambiguous exports and conflicting artifact hashes, and emit 0 changes to source-closed-v1 or trusted-dependencies-v1 behavior. [R1]
- When `PICKLE_PROVIDER_INITIALIZED` binds a constructor before a successful canonical dump and the same immutable bytes reach load, the system shall emit 1 initialized-provider witness only when cached module, type and qualified export identities remain stable. Historical unknown annotations alone shall emit 0 reconstruction effects under the declared trusted-initialization assumptions. [R2]
- When `PICKLE_RECORD_RECONSTRUCTED` selects the v2 model, the system shall evaluate at most 8 single-inheritance Exception classes and 512 evidence states for closed type constants, delegated constructors, bounded literal interpolation, instance fields and reconstruction arguments, or retain the active finding. [R3]
- When `PICKLE_LOOKUP_MUTATED` contains source-visible module-cache eviction, export/class/qualname mutation, reload, registry changes, persistent IDs, custom unpicklers, audit/import hooks, descriptors or metaclasses, the system shall reject the witness with 0 negative decisions. [R4]
- When `PICKLE_V2_ADMITTED` consumes a candidate, the system shall select exactly 1 constructor contract before state modeling and regenerate selected source, model, contract-set, export, byte-flow and reconstruction hashes from current captured bytes within 64 sources and 1000000 bytes per source. [R5]
- When `PICKLE_FAMILY_MEASURED` runs, the system shall preserve all 96 exposed labels, all 2 pickle true positives and all 2 pickle unclear cases, report the remaining 32 false-positive outcomes separately, and emit 0 fresh-held-out or precision claims from unlabelled controls. [R6]
- When `PICKLE_V2_QUALIFIED` checks a candidate, the system shall add 0 production modules, 0 dependencies and 0 target executions and finish within 30 seconds or retain the original finding as incomplete. [R7]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Versioned contracts preserve prior analysis
  Given PICKLE_V2_SELECTED has two unambiguous contracts
  When PICKLE_V2_ADMITTED runs
  Then R1 and R5 select one current constructor contract

Scenario: Reconstruction does not repeat historical annotations
  Given PICKLE_PROVIDER_INITIALIZED binds the exact cached type
  When PICKLE_RECORD_RECONSTRUCTED evaluates delegated constructors
  Then R2 and R3 model reconstruction effects within 512 evidence states

Scenario: Runtime lookup counterevidence retains the finding
  Given PICKLE_LOOKUP_MUTATED alters the cached type identity
  When PICKLE_V2_ADMITTED runs
  Then R4 emits zero negative decisions

Scenario: Family outcomes are measured without target execution
  Given PICKLE_FAMILY_MEASURED is requested
  When PICKLE_V2_QUALIFIED finishes
  Then R6 preserves the labelled cases and R7 performs zero target executions
```

## SHOULD — Technical/structural
- Contract wire schema stays factory.provider-contract.v1; v2 profile owns a canonical sorted set and aggregate model/contract digests. V1 still requires its single v1 model. Reject duplicate export or first-class identities, contradictory overlapping artifacts and unknown models before scanning.
- V2 single-inheritance chains end in canonical Exception. Reject class decorators, class keywords/metaclasses, custom __new__, reducers, state hooks, slots and descriptors. Allow ordinary __str__/__repr__ declarations only as non-invoked display methods; reject their decorators or dynamic defaults. Literal class constants cannot replace protected reconstruction identities.
- Model BaseException allocation args, zero-argument lexical super().__init__ delegation along the captured MRO, closed literal arguments/defaults, None guards, self-field writes, bounded f-strings over owned literals (including repr of bytes) and tuple self.args. No arbitrary constructor calls, attribute protocols, dynamic values or indirect super dispatch. Reconstruct from actual reduced args and separately apply the validated instance-state BUILD semantics.
- Definition headers may have historical unknown annotations under explicit trusted initialization, but captured calls, named expressions, decorators or writes contradicting class/export stability reject. This model does not audit initialization safety or promise absence of arbitrary Python runtime hooks.
- Initialized identity requires the same source-bound constructor class before dump, canonical save_global identity checking, exact module/qualname/export resolution on load, and no source-visible cache, class, registry or hook changes. Qualified-name and protocol compatibility mappings not explicitly modeled decline.
- Existing trusted-initialization, immutable-artifact, no-runtime-monkey-patching and canonical-CPython assumptions remain explicit in each finding. Canonical sys.audit lookup events remain a stated runtime boundary; observed audit/import hook registration invalidates the witness.
- Canonical contract selection is based on current captured constructor import/export binding, never the first model that succeeds. The selected contract and aggregate set identity both enter the witness and independent admission. Conditional decisions are not reused through default caches or checkpoints.
- Use the original 23-repository/96-claim exposed panel with identical added provider contexts across comparison profiles. H280-077 is an actual candidate, not a promised win. Original H280-021 must remain qualified in the set profile. No package-name, test-path or label-based policy.

## SHOULD NOT — Implementation details
- Do not equate local dumps/loads syntax with safe object-graph reconstruction.
- Do not add multidict/native-driver trust solely to force a case to pass.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | PICKLE_LOOKUP_MUTATED | retain original finding |
| 2 | PICKLE_PROVIDER_INITIALIZED | check cached identity and actual reconstruction effects |
| 3 | PICKLE_V2_ADMITTED | select one contract and regenerate the complete witness |

## Consolidated implementation packet

The historical `plans/pickle-reconstruction-v2.md` packet is retained here with its original task states and evidence boundary. Consolidation does not declare its tasks complete.

### Implementation packet: pickle-reconstruction-v2
Spec: specs/pickle-reconstruction-v2.md
Architect verdict: PASS

## Tasks (atomic — each independently shippable)
- [ ] T1 | slice=factoryline | files=factoryline/finite_capture.py,tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k pickle_reconstruction317 -q` | Validate canonical versioned contract sets and model initialized Exception reconstruction without repeating historical headers.
- [ ] T2 | slice=factoryline | files=factoryline/runtime_audit_integrity.py,factoryline/primitive_observation_binding.py,tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k pickle_reconstruction317 -q` | Bind cached class lookup and byte dominance, reject mutations/hooks, and independently regenerate selected-contract admission.
- [ ] T3 | slice=factoryline | files=tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k pickle_reconstruction317 -q` | Qualify actual candidates and all pinned controls, then freeze and measure complete matched family outcomes.

## Evidence boundary
Latest completed pickle replay: 2 TP / 32 FP / 2 unclear; H280-021 is the only removed FP. Neither model fixtures nor a policy change count as new detection or precision. All unsupported cases stay active with exact reasons; no claim that 32 cases are resolved before measurement.

ECC architecture approval: `.factory/precision317/ecc-v2-architecture.md`. This approves the bounded design, not implementation or measured removals.
