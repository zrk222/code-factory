# Spec: remaining-serializer-duplication
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Delete the 59 direct private canonical JSON encoding bodies across three existing contracts and use one package implementation per existing byte contract without changing receipt bytes or invalid-value exceptions.
### User roles
- Local receipt producers and verifiers.
### Requirements (EARS)
- The system shall emit identical JSON bytes using the existing sorted-key, compact-separator and ASCII or Unicode profile, verified by `canonical_bytes_preserved`.
- If a value contains an unsupported value under its existing strict or legacy encoding profile, the system shall reject the value with the existing exception type, verified by `invalid_values_rejected`.
- The system shall emit bytes through one implementation for the 59 existing module serializer names and omit all local JSON encoding bodies while retaining the three original v/payload keyword signatures, verified by `duplicate_bodies_deleted`.
### Acceptance criteria (Gherkin)
```gherkin
Scenario: receipt compatibility
  Given the 59 declared serializer modules and Unicode nested values
  When each existing serializer name is called
  Then `canonical_bytes_preserved` is true
  Then `invalid_values_rejected` is true
  Then `duplicate_bodies_deleted` is true
```
## SHOULD — Technical/structural
- No new module, persistent cache, service, command or data format. Existing non-finite and ASCII contracts remain distinct.
## SHOULD NOT — Implementation details
- Domain-specific exception wrappers and atomic write semantics remain outside this direct-encoder change.
### Declared facts
- duplicate_bodies: 59 direct JSON encoders across strict UTF-8, legacy UTF-8 and legacy ASCII profiles
