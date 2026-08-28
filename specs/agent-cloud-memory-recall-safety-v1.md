# Spec: agent-cloud-memory-recall-safety-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Add supervised, exact-scope persistent-memory recall to the clean-room local Convex pilot. Filter before ranking, quarantine persistent instruction-like content, and explain provenance without granting authority. This does not claim universal prompt-injection detection or access WizeMe application source.

### Requirements (EARS)

- When recall is requested, the system shall return `MEMORY_RECALL_SCOPED` after deriving workspace and agent from AgentSpec, applying normalized exact subject and purpose equality before ranking, and ordering confidence descending then creation time descending.
- When active records are evaluated, the system shall return `MEMORY_QUARANTINE_ENFORCED` after excluding every quarantined record from recall.
- When recall succeeds, the system shall return `MEMORY_AUTHORITY_SEPARATED` after exposing exactly 0 authority-bearing fields.
- When one record is recalled, the system shall return `MEMORY_RECALL_EXPLAINED` after showing source, purpose, provenance, confidence, policy version, trust label, safety state, creation time, and a bounded match explanation.
- When suspicious content is stored or corrected, the system shall return `MEMORY_QUARANTINED` after retaining it as lifecycle evidence and excluding it from recall.
- When an eligible write or correction succeeds, the system shall return `MEMORY_RECALL_ELIGIBLE` after applying the same deterministic classifier.
- When quarantine evidence is appended, the system shall return `MEMORY_CONTENT_REDACTED_FROM_AUDIT` after proving audit and receipt metadata omit memory content.
- If recall limit is below the minimum of 1 item or above the maximum of 20 items, the system shall return `E_INVALID_LIMIT` before recall.
- When the recall surface renders at 390 and 1440 CSS pixels, the system shall return `MEMORY_RECALL_UI_RESPONSIVE` after exposing exact-scope controls and provenance explanations without horizontal overflow.
- The system shall return `CONVEX_ONLY_STACK` after proving Convex is the only application backend.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Filter before ranking
  Given eligible records with matching and nonmatching purposes
  When exact-scope recall is requested
  Then MEMORY_RECALL_SCOPED returns only exact matches ordered by confidence and recency

Scenario: Quarantine persistent instructions
  Given content containing one declared persistent-instruction phrase
  When the content is stored and recalled
  Then MEMORY_QUARANTINED retains evidence and MEMORY_QUARANTINE_ENFORCED excludes it
  And MEMORY_CONTENT_REDACTED_FROM_AUDIT proves audit and receipt metadata omit the content

Scenario: Reclassify a correction
  Given one quarantined active memory
  When an Operator appends safe corrected content
  Then MEMORY_RECALL_ELIGIBLE marks only the active successor eligible for recall

Scenario: Explain recall without authority
  Given one eligible exact-scope record
  When the record is recalled
  Then MEMORY_RECALL_EXPLAINED shows bounded provenance
  And MEMORY_AUTHORITY_SEPARATED shows zero authority fields

Scenario: Render scoped recall
  Given governed memory records
  When the memory surface renders at 390 and 1440 CSS pixels
  Then MEMORY_RECALL_UI_RESPONSIVE exposes scope controls and explanations without horizontal overflow
```

## SHOULD - Technical/structural

- ADR reference: `adr/agent-cloud-memory-recall-safety-v1.md`.
- Convex API: `products/agent-cloud/app/convex/memory.ts`.
- UI: `products/agent-cloud/app/src/components/MemoryPanel.tsx`.

### Authorized bounded constants

- Policy version is `memory-policy.v1`; trust label is `untrusted-context`; UI recall limit is 5.
- Classifier phrases are exactly `ignore previous instructions`, `reveal secrets`, `system prompt`, `override policy`, and `exfiltrate`.
- Content maximum is 2000; subject 200; source and purpose 300; provenance and correction reason 500 characters.
- Confidence is 0 through 100; retention is 1 through 3650 days; recall limit is 1 through 20.
- The existing governed-memory defaults remain confidence 96, retention 365 days, and 86400000 milliseconds per day.
- Existing adjacent lifecycle input bounds remain import payload 5000 characters and secret reference 240 characters.
- Browser widths are 390 and 1440 CSS pixels; icon sizes are 13, 15, 16, 17, 18, 20, 21, 22, 24, 26, and 27 CSS pixels.
- Typography weights are 400, 500, 600, 700, and 800; `PROOF LINE 01` remains authorized.
- Test and browser commands time out after 120 seconds.

## SHOULD NOT - Implementation details

- No semantic/vector search, hosted tenancy, OIDC, billing, remote model invocation, autonomous deployment, or universal safety claim.
- No memory content in quarantine audit or receipt metadata.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | `MEMORY_RECALL_SCOPED` is absent | block recall |
| 2 | `MEMORY_QUARANTINE_ENFORCED` is absent | block recall |
| 3 | `MEMORY_AUTHORITY_SEPARATED` is absent | block recall |
| 4 | `MEMORY_RECALL_EXPLAINED` is absent | block recall |
| 5 | `MEMORY_QUARANTINED` exists | retain lifecycle evidence and exclude the record from recall |
| 6 | `MEMORY_RECALL_ELIGIBLE` exists | allow only exact-scope retrieval |
| 7 | `MEMORY_CONTENT_REDACTED_FROM_AUDIT` is absent | block quarantine write success |
| 8 | `E_INVALID_LIMIT` exists | return exactly 0 recalled records |
| 9 | `MEMORY_RECALL_UI_RESPONSIVE` is absent | block UI release |
| 10 | `CONVEX_ONLY_STACK` is absent | block release |
