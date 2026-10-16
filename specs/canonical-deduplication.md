# Spec: canonical-deduplication
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
Delete the 23 identical private canonical JSON serializer bodies and use one package implementation without changing receipt bytes or invalid-value exceptions.
### User roles
- Local receipt producers and verifiers.
### Requirements (EARS)
- The system shall emit identical UTF-8 JSON bytes with sorted keys, compact separators and unescaped Unicode, verified by `canonical_bytes_preserved`.
- If a value contains NaN, infinity, an unsupported object or invalid Unicode, the system shall reject the value with the existing exception type, verified by `invalid_values_rejected`.
- The system shall emit bytes through one implementation for the 23 existing module serializer names and omit all local duplicate definitions in those modules, verified by `duplicate_bodies_deleted`.
### Acceptance criteria (Gherkin)
```gherkin
Scenario: receipt compatibility
  Given the 23 declared serializer modules and Unicode nested values
  When each existing serializer name is called
  Then `canonical_bytes_preserved` is true
  Then `invalid_values_rejected` is true
  Then `duplicate_bodies_deleted` is true
```
## SHOULD — Technical/structural
- No new module, persistent cache, service, command or data format.
## SHOULD NOT — Implementation details
- Other serializer variants and atomic write semantics remain outside this exact-equivalence change.
### Declared facts
- duplicate_bodies: 23 identical serializer definitions
