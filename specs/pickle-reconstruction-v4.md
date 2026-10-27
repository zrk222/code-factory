# Spec: pickle-reconstruction-v4
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Use one source-regenerated typed reconstruction graph for the remaining pickle family, rather than one negative proof per library class. Byte-origin observations are inputs, not safety decisions. All unsupported effects remain unresolved.

### Requirements (EARS)
- When `PICKLE_GENERIC_SELECTED` requests typed-pickle-reconstruction-v4, the system shall emit exactly 1 selected contract under trusted-dependencies-v2 and emit 0 broadened negative decisions for the prior v1, v2 and v3 models. [R1]
- When `PICKLE_GENERIC_GRAPH` evaluates captured source and effect bindings, the system shall emit a graph with at most 512 nodes, depth 8, 16 source classes and 64 artifacts; each captured scalar shall contain at most 16384 bytes and each integer at most 4096 bits. Caller-supplied graph authority shall be rejected. [R2]
- When `PICKLE_GENERIC_RECIPE` models object, list-subclass or ordered-mapping reconstruction, the system shall validate protocol 0/1 and protocol 2–5 allocation, insertion and state recipes separately against exact canonical runtime artifacts within 512 evidence states before emitting 1 negative witness. [R3]
- When `PICKLE_GENERIC_STATE` includes mutable aliases or cycles, the system shall store explicit node identities and references; immutable-tuple cycles, unresolved descriptors, metaclasses, native providers, callbacks and state effects shall emit 0 negative witnesses. [R4]
- When `PICKLE_GENERIC_HOOK` selects a paired source-owned state recipe, the system shall validate exact class/MRO, method AST, argument/state graph and insertion branch identities; source-visible provider mutations or missing backend/typecaster facts shall emit 0 negative witnesses. [R5]
- When `PICKLE_GENERIC_MEASURED` qualifies the candidate, the system shall emit outcomes for all 37 original claims, retain all 2 true positives and all 2 unclear cases, and emit removals, remaining cases, abstentions and matched source/runtime identities separately with 0 fresh-held-out claims. [R6]
- When `PICKLE_GENERIC_QUALIFIED` completes, the system shall add 0 production modules, 0 dependencies and 0 target-repository executions, and emit focused source tests plus controlled scanner-owned runtime-conformance observations. [R7]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: One graph handles related source classes
  Given PICKLE_GENERIC_SELECTED has unambiguous captured source
  When PICKLE_GENERIC_GRAPH evaluates the selected inputs
  Then R1 and R2 emit one bounded source-regenerated graph

Scenario: Reconstruction is protocol specific
  Given PICKLE_GENERIC_RECIPE has current canonical runtime artifacts
  When PICKLE_GENERIC_STATE includes a mutable reference
  Then R3 and R4 validate allocation and preserve node identity

Scenario: Unknown effects never become safety facts
  Given PICKLE_GENERIC_HOOK lacks a backend or effect premise
  When PICKLE_GENERIC_RECIPE is evaluated
  Then R5 emits zero negative witnesses

Scenario: Family verification retains original controls
  Given PICKLE_GENERIC_MEASURED contains 37 original claims
  When PICKLE_GENERIC_QUALIFIED finishes
  Then R6 retains the controls and R7 records no target-repository execution
```

## SHOULD — Technical/structural
- Reuse the existing capture, source-call binder, contract set, graph/source hashes and independent admission. Keep all semantic limits model-specific; architecture caps remain unchanged.
- Graph nodes comprise exact scalar values, tuple/list/dict/OrderedDict nodes, identity references and source instances with class, allocation, base items and state. Exact builtin data-only abstract leaves require a source-proven operation/type; annotations or isinstance alone do not prove exact type.
- Plain object allocation requires verified default object allocation and source MRO. List and mapping subclass insertion must model any invoked override. Slots and paired state hooks are admitted only through exact source-regenerated recipes, never an API-name allowance.
- Requests helper-produced objects and Psycopg row/index state must share the same graph. SQL/source bindings are candidate premises; a literal query does not establish the decoder or backend contract by itself.
- Bind every runtime facility used: pickle/copyreg, builtin containers, OrderedDict, and any lock, enum, datetime or typing recipe. Unknown native/provider artifacts remain unresolved.
- A v4-only caller context may declare an exact receiver domain using captured class/method AST identities and an explicit receiver lookup environment: selected attributes resolve only through source-owned class attributes, with no instance shadow or fixture/setup override. Regenerate the full source MRO, reject lookup descriptors/custom attribute methods, validate every declared alternative and reject contradictory captured setup/fixture writes. Emit DECLARED_CALLER_RECEIVER_DOMAIN and DECLARED_UNSHADOWED_RECEIVER_LOOKUP assumptions and state that these are conditional premises, not runtime observations or claims about arbitrary callers. For captured test discovery, enumerate every concrete captured class inheriting the selected method; a subset may not authorize removal of the shared finding. Old model contracts and assumptions remain unchanged.
- Controlled conformance tests may execute trusted scanner-owned fixture classes to observe canonical unpickler callbacks for protocols 0–5. Never import, compile or execute target-repository classes. Such tests measure model conformance, not held-out precision.

## SHOULD NOT — Implementation details
- Do not substitute another isolated class fix for the shared graph or declare the family complete from a smaller successful subset.
- Do not use repository/test-path allowlists, labels, unknown values or local dump syntax as reconstruction authority.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | PICKLE_GENERIC_HOOK | validate captured effects and backend identities |
| 2 | PICKLE_GENERIC_RECIPE | validate protocol-specific reconstruction |
| 3 | PICKLE_GENERIC_MEASURED | report every original claim and retained control |

## Consolidated implementation packet

The historical `plans/pickle-reconstruction-v4.md` packet is retained here with its original task states and evidence boundary. Consolidation does not declare its tasks complete.

### Implementation packet: pickle-reconstruction-v4
Spec: specs/pickle-reconstruction-v4.md
Architect verdict: PASS

## Tasks (atomic — each independently shippable)
- [ ] T1 | slice=factoryline | files=factoryline/finite_capture.py,tests/test_context_efficiency.py | verify=`python -m pytest tests/test_context_efficiency.py -k pickle -q` | Implement one bounded graph with identity, source-object/container recipes and protocol-specific reconstruction.
- [ ] T2 | slice=factoryline | files=factoryline/runtime_audit_integrity.py,factoryline/primitive_observation_binding.py,tests/test_finite_capture_origins.py | verify=`python -m pytest tests/test_finite_capture_origins.py -k pickle -q` | Bind generic source/driver facts through independent native admission while preserving raw diagnostics and previous model behavior.
- [ ] T3 | slice=factoryline | files=tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k pickle -q` | Verify backend/state/identity counterexamples and freeze one matched complete37 replay.

## Evidence boundary
Latest completed matched replay: 2 TP, 30 FP and 2 unclear, exposed precision 6.25%. Shared imported-symbol dump/load observations cover30 FP but authorize zero removals. The remaining family and fresh publication target remain incomplete. Source-only artifacts and controlled runtime conformance are not target deployment evidence.
