# Spec: credential-authority-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Bind a literal credential declaration to a configured Flask application, request comparison, session grant and session consumer. Preserve original diagnostics and distinguish unsupported bindings from supported local wiring. This is a positive validator, not a claim that other credentials are safe.

### Requirements (EARS)
- When `AUTHORITY_REQUESTED` selects a credential declaration, the system shall resolve exactly 1 literal declaration and its configuration transfer from captured bytes within 512 evidence states, or return incomplete. [R1]
- When `AUTHORITY_COMPARED` links request input to the configured credential, the system shall emit 1 supported authority witness only after resolving an equality-dependent session grant and a matching session consumer. [R2]
- When `SIGNING_AUTHORITY_REQUESTED` selects SECRET_KEY, the system shall reject promotion without the same configured application and session authority chain, with 0 promotions from configuration loading alone. [R3]
- When `AUTHORITY_AMBIGUOUS` contains wildcard shadows, overwritten configuration, a different application, unknown provider identity, an unreachable comparison or missing authority use, the system shall retain the original diagnostic and emit 0 supported authority witnesses. [R4]
- When `AUTHORITY_ADMITTED` consumes a witness, the system shall reject any altered source, declaration, configuration or consumer span after regeneration from current captured bytes within 512 evidence states, with 0 duplicate diagnostic identities. [R5]
- When `AUTHORITY_MEASURED` runs, the system shall emit separate supported-promotion and active-precision counts while retaining all 96 exposed labels and all 6 known true-positive diagnostics, with 0 fresh-held-out claims from replay. [R6]
- When `AUTHORITY_IMPLEMENTED` is checked, the system shall add 0 production modules, 0 dependencies and 0 target executions; qualification shall finish within 30 seconds or remain incomplete. [R7]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Configured password controls session authority
  Given AUTHORITY_REQUESTED selects a literal declaration
  When AUTHORITY_COMPARED resolves the configured value and session chain
  Then R1 and R2 admit one source-bound witness

Scenario: Configuration alone does not establish authority
  Given SIGNING_AUTHORITY_REQUESTED has no session authority chain
  When AUTHORITY_AMBIGUOUS is evaluated
  Then R3 and R4 emit zero supported witnesses

Scenario: Independent admission and measurement retain identities
  Given AUTHORITY_ADMITTED contains an altered source span
  When AUTHORITY_MEASURED runs
  Then R5 and R6 preserve the original diagnostic and labels

Scenario: Bounded validation performs no target execution
  Given AUTHORITY_IMPLEMENTED is checked
  When qualification runs
  Then R7 adds zero dependencies and executes zero target programs
```

## SHOULD — Technical/structural
- Reuse the native signing configuration inventory, request-source binding, provider stability, path feasibility and supported-precondition admission.
- A witness records source hashes, declaration/configuration/comparison/grant/consumer spans, framework assumptions and proof scope `local_static_wiring`; deployment and runtime exploitability remain unassessed.
- Recognize source-proven imported Flask/request/session aliases; a wildcard import cannot be assumed disjoint without captured export evidence. Missing exports mean incomplete.
- Accept a uniquely assigned Flask application and one from_object(__name__) transfer, with no relevant key replacement or opaque configuration reload. Request value aliases require unique reaching assignments.
- The equality-success branch must write a literal truthy session value, and a separately bound consumer must check that same session key to guard access. An equality without authority effect is not enough.
- Source closure cannot borrow unrelated pickle model assumptions. An explicit additional assumption requires its own versioned contract and measurement profile.
- Renamed generic fixtures and overwritten-key, shadowed-provider, different-app, dead-branch, unused-session and configuration-only controls are mandatory. Exposed source cases qualify behavior but are not holdout data.

## SHOULD NOT — Implementation details
- Do not classify from repository names, labels, paths, literal spelling or model verdicts.
- Do not lower severity, remove original rows or count a promoted existing true positive as a new detection.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | AUTHORITY_AMBIGUOUS | return incomplete and preserve the diagnostic |
| 2 | SIGNING_AUTHORITY_REQUESTED | require the same application and session authority chain |
| 3 | AUTHORITY_ADMITTED | regenerate the complete witness from current bytes |

## Consolidated implementation packet

The historical `plans/credential-authority-v1.md` packet is retained here with its original task states and evidence boundary. Consolidation does not declare its tasks complete.

### Implementation packet: credential-authority-v1
Spec: specs/credential-authority-v1.md
Architect verdict: NEEDS_WORK

## Tasks (atomic — each independently shippable)
- [ ] T1 | slice=factoryline | files=factoryline/semantic_credential_sensor.py,tests/test_semantic_credential_sensor.py | verify=`python -m pytest tests/test_semantic_credential_sensor.py -k credential_authority315 -q` | Bind declaration, configured app, request comparison and session authority using existing native predicates; reject unsupported provider or mutation evidence.
- [ ] T2 | slice=factoryline | files=factoryline/primitive_observation_binding.py,tests/test_runtime_audit_integrity.py | verify=`python -m pytest tests/test_runtime_audit_integrity.py -k credential_authority315 -q` | Independently admit the source-bound positive witness on the original diagnostic identity and measure retention separately from precision.

## Evidence boundary
The latest complete exposed replay remains 6 TP / 75 FP / 11 unclear. Positive support of an existing TP does not increase that numerator. This feature is complete only with independently regenerated public-path evidence; unavailable provider or export facts remain incomplete.

## Feasibility stop
ECC review `.factory/precision315/ecc-authority-plan.md` found unresolved wildcard/provider effects, application escape into FlaskDB and session-signing assumptions. Root inspected the captured FlaskDB class: it stores the application and registers callbacks. No implementation is admitted by this packet. Do not replace these missing premises with package names or generic fixture passes. Resume only with a source-backed effect/export contract that closes an actual candidate.
