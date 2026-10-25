# Spec: jev-informed-inputs-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Capture one reusable, bounded, source-linked sink evidence packet for CF native
validators and secondary JEV review. Replace whole-file-only context with exact
value transfers, provider bindings, caller source and explicit uncertainty. JEV
has no filesystem or tool access; the host supplies all evidence. More bytes or
a schema-valid packet cannot establish actionability.

### User roles
- Operator authorizes source capture and optional Vercel Gateway dispatch.
- CF validator establishes source identity and the scope of observed facts.
- JEV reviewer assesses contextual claims without overriding native CF results.

### Requirements (EARS)
- When `SINK_HASH_MISMATCH_REQUESTED` contains a sink or expanded-dependency source hash mismatch, the system shall return SINK_SOURCE_STALE and dispatch 0 model requests. [R1]
- When `SINK_SPAN_INVALID_REQUESTED` cannot locate exactly 1 AST call at the declared span, the system shall return SINK_LOCATION_UNRESOLVED and dispatch 0 model requests. [R2]
- When `SINK_CONTEXT_CAPTURED` succeeds, the system shall emit the exact sink, enclosing callable, lexical imports, direct argument expressions and source references for each observed value definition. [R3]
- When `SINK_BINDING_REPLACED` contains an import, declaration, exception capture, match capture or ordinary write replacing a tracked value, the system shall preserve 1 unresolved binding fact and grant 0 local-origin safety claims. [R4]
- When `SINK_CALLER_RESOLVED` has 1 source-bound callee and receiver with exact argument/default binding and supported return control flow, the system shall record source-linked actual-to-formal and return edges; unresolved dispatch shall remain an explicit unknown. [R5]
- When `SINK_BOUNDARY_UNDECLARED` has no source-supported authority or caller contract, the system shall return NEEDS_CONTEXT and grant 0 actionable-defect certificates from API presence alone. [R6]
- When `SINK_EVIDENCE_RECORDED` succeeds, the system shall emit 1 fact ledger with observed, inferred or unknown labels, and bind every observed fact to source path, source SHA256 and inclusive line span. [R7]
- When `SINK_BUDGET_EXHAUSTED` reaches 64 source files, 512 traversed evidence states or 64000 UTF-8 output bytes, the system shall emit explicit truncation and grant 0 complete-evidence claims. [R8]
- When `JEV_SINK_REQUEST_BUILT` succeeds, the system shall emit 1 packet of at most 64000 bytes with supporting source, contradictory source, unresolved symbols, scope boundaries and the exact actionability criterion, while forwarding 0 expected labels. [R9]
- When `JEV_SINK_REVIEWED` returns a secondary judgment, the system shall preserve all raw CF findings, severities and deterministic failures unchanged. [R10]
- When `SINK_SOURCE_CHANGED` occurs in the sink or any expanded source/configuration/provider dependency after capture, the system shall reject the stale packet before model dispatch or native certificate admission. [R11]
- When `SINK_ACCURACY_REPORTED` follows a frozen family run, the system shall emit 1 result ledger of at most 64000 bytes with decided precision, TP retention, coverage, abstentions, input failures and the full cohort denominator separately; exposed data shall retain development-only status. [R12]

- When `SINK_INPUT_BOUND_EXCEEDED` receives more than 1000000 bytes in 1 source or more than 32000000 bytes in the captured inventory, the system shall return SINK_INPUT_UNASSESSED before parsing the oversized source and dispatch 0 model requests. [R13]
- When `SINK_OUTBOUND_SECRET_DETECTED` finds a recognized secret pattern in any outbound string within the 64000-byte packet, the system shall reject the outbound packet and dispatch 0 model requests; a redacted derivative shall require a separate binding rather than claiming original raw-source identity. [R14]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Source identity and exact sink are mandatory
  Given `SINK_HASH_MISMATCH_REQUESTED` with changed source bytes
  And `SINK_SPAN_INVALID_REQUESTED` with an ambiguous span
  When capture validates the candidate
  Then SINK_SOURCE_STALE or SINK_LOCATION_UNRESOLVED causes 0 provider requests

Scenario: Definitions and transfers have explicit limits
  Given a local dump, a helper return and a deserialization call
  When SINK_CONTEXT_CAPTURED resolves their source
  Then source-linked definitions and transfer edges are observed
  And a replaced binding or unresolved helper remains unknown
  And a local serialization origin grants 0 reducer-safety claims

Scenario: Missing authority cannot become a defect certificate
  Given SINK_BOUNDARY_UNDECLARED for a generic library method
  When the native validator consumes the evidence packet
  Then NEEDS_CONTEXT remains and raw diagnostics are unchanged

Scenario: Context budget cannot look like complete coverage
  Given SINK_BUDGET_EXHAUSTED
  When evidence is emitted
  Then truncation and missing source are explicit
  And 0 complete-evidence claims are emitted

Scenario: Secondary review cannot change primary outcomes
  Given a native failure and a contradictory JEV decision
  When JEV_SINK_REVIEWED is recorded
  Then the native failure, source hash and raw severity remain unchanged

Scenario: Accuracy has a fixed denominator
  Given the frozen 37-case exposed deserialization family
  When SINK_ACCURACY_REPORTED includes unavailable or abstaining cases
  Then all 37 cases remain in the ledger
  And no fresh held-out claim is produced


Scenario: Every input event has a declared validation obligation
  Given `SINK_HASH_MISMATCH_REQUESTED`
  Given `SINK_SPAN_INVALID_REQUESTED`
  Given `SINK_CONTEXT_CAPTURED`
  Given `SINK_BINDING_REPLACED`
  Given `SINK_CALLER_RESOLVED`
  Given `SINK_BOUNDARY_UNDECLARED`
  Given `SINK_EVIDENCE_RECORDED`
  Given `SINK_BUDGET_EXHAUSTED`
  Given `JEV_SINK_REQUEST_BUILT`
  Given `JEV_SINK_REVIEWED`
  Given `SINK_SOURCE_CHANGED`
  Given `SINK_ACCURACY_REPORTED`
  Given `SINK_INPUT_BOUND_EXCEEDED`
  And `SINK_OUTBOUND_SECRET_DETECTED`
  When the source evidence contract is checked
  Then each declared obligation has a source-bound observation or an explicit unknown
```

## SHOULD — Technical/structural
- Reuse SourceSnapshotIndex, CapturedImportInventory, binding_occurrences and
  existing call binding; no second repository graph or production dependency.
- Share captured source and indexes between native CF validators and JEV packet
  preparation. Cache only exact source/dependency/policy identities.
- Keep exact useful callable bodies and imports; preserve type signatures for
  referenced but unexpanded helpers. Record every omitted consequential body.
- Author comments, source text, tool reports and model output are untrusted data.
- One captured call target never establishes exhaustive callers. Unbound receivers,
  argument expansions, generators and unknown return paths retain explicit gaps.
- Host validators establish integrity and their declared semantics; probabilities
  do not establish source reachability, runtime behavior or model correctness.

## SHOULD NOT — Implementation details
- Do not lower 0.9/0.1 thresholds to turn abstentions into claimed gains.
- Do not infer harmlessness from test paths or local pickle origin alone.
- Do not equate a known/resolved status string with source-supported semantics.
- Do not expose keys, execute target code, fetch undeclared remote dependencies,
  add another model framework or remove uncertainty to obtain a passing score.

## Authorized parameters
- max_sources = 64
- max_states = 512
- max_packet_bytes = 64000
- max_source_bytes = 1000000
- max_inventory_bytes = 32000000

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | SINK_SOURCE_STALE | reject packet and dispatch 0 requests |
| 2 | SINK_LOCATION_UNRESOLVED | retain unknown sink and dispatch 0 requests |
| 3 | SINK_BINDING_REPLACED | retain unknown origin without safety admission |
| 4 | SINK_BOUNDARY_UNDECLARED | retain NEEDS_CONTEXT |
| 5 | SINK_BUDGET_EXHAUSTED | emit incomplete context without complete claim |
| 6 | SINK_SOURCE_CHANGED | reject stale evidence before admission |
| 7 | JEV_SINK_REVIEWED | record advisory observation without native override |

## Consolidated implementation packet

The historical `plans/jev-informed-inputs-v1.md` packet is retained here with its original task states and evidence boundary. Consolidation does not declare its tasks complete.

### Implementation packet: jev-informed-inputs-v1
Spec: specs/jev-informed-inputs-v1.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Shared source-linked native sink evidence with scope and binding checks.
2. Deterministic packet validation and bounded source expansion for JEV.
3. Frozen repaired-family diagnosis, then independent fresh evaluation.

## Tasks (atomic — independently reviewable)
- [ ] T1 | slice=factoryline | files=factoryline/finite_capture.py,factoryline/runtime_audit_integrity.py,tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k sink_context -q` | Capture observed sink expressions, definitions, bindings, enclosing scope and explicit unknowns using existing AST and source indexes. No new production module.
- [ ] T2 | slice=factoryline | files=factoryline/analysis_evidence.py,factoryline/jev_classifier.py,tests/test_audit_rule_search.py | verify=`python -m pytest tests/test_audit_rule_search.py -k informed -q` | Resolve bounded captured helpers/callers and format the shared evidence for secondary review; do not invent missing authority or execute code.
- [ ] T3 | slice=scripts | files=scripts/evaluate_jev.mjs,scripts/evaluate_jev.test.mjs | verify=`node --test --test-name-pattern=informed scripts/evaluate_jev.test.mjs` | Enforce strict references and evidence states, reject source drift and label leakage, preserve native outcomes.

- [ ] T4 | slice=factoryline | files=factoryline/semantic_credential_sensor.py,tests/test_semantic_credential_sensor.py | verify=`python -m pytest tests/test_semantic_credential_sensor.py -k sink_context -q` | Resolve the modeled Flask body-reader call shape and bytes/text source kind through existing source-bound request and call-binding validators; retain malformed, unknown and replaced providers.

## Acceptance and measurement
The original Study287 results (36 abstentions, 1 input-bound unassessed) remain
immutable. Freeze the new source builder, rubric and same-family inputs before
rerun. Keep labels outside requests. Report native raw finding precision and
secondary recommendation precision separately with actual positive denominator,
TP retention, uncertainty-inclusive coverage and all input errors. This is exposed
development diagnosis, not a fresh holdout. Meet the complete original release
and accuracy requirements on an independently frozen fresh cohort afterward.

## Current boundaries
No target imports/execution, publication or release. Provider access is explicit,
locally encrypted, short-lived and quota-bound. Native CF validators remain the
primary decision path when JEV is absent or disagrees.
