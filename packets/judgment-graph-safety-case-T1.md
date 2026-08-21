# TASK PACKET T1 — judgment-graph-safety-case
<!-- One session. Finish, verify, stop. Context resets after this. -->

## Your single task
Add strict Capsule validation, proposal, independent promotion, reconsideration, and deterministic status.

## Slice (you may only create/modify files here + tests)
judgment-store

## Files in scope (R_f — read nothing else except context/PROGRESS.md)
- (new files in slice)

## Governing spec excerpt
### Governing requirements (complete blocks)
- The system shall accept only `factory.judgment.capsule.v1` Capsule records
  with exact schema fields, normalized workspace-relative scopes, bounded text,
  non-empty proof obligations, an owner, and an ISO-8601 review date.
- When a named human proposes a Capsule, the system shall store the Capsule
  with `state=proposed` and shall exclude that Capsule from Change Safety Case
  matching.
- If the promotion actor differs from the proposer, the system shall store `state=active` and the named promoter for a valid proposed Capsule.
- If the promotion actor equals the proposer, the system shall reject promotion without changing the Capsule store.
- If a named human records reconsideration for an active Capsule, the system shall store the successor proposal ID and retain the active Capsule until independent promotion.
- If a Change Safety Case receives explicit changed paths, the system shall emit matching active Capsule IDs and every unmatched path as `unclassified_changed_path`.
- If a matching active Capsule has an invalid or absent obligation receipt, the system shall emit `route=RED` and the exact missing obligation IDs.
- When no active Capsule matches an explicit changed path, the system shall
  route `GREEN` only as `routine_unclassified`; the result shall retain the
  unclassified paths and shall not claim that the change is safe or approved.
- If a Capsule store or Capsule is malformed, the system shall fail closed with
  `JUDGMENT_CAPSULE_INVALID` and shall not use an older record as a fallback.
- The system shall emit active Capsule facts into Graph Ops and the local Graph
  Ops UI without changing Capsule state or granting execution authority.
- Data model: tracked `judgment/capsules.json` uses schema
  `factory.judgment.store.v1`. A Capsule uses schema
  `factory.judgment.capsule.v1`, state `proposed|active|superseded`, unique
  ID, proposer/promoter, scoped paths, evidence references, named proof
  obligations, owner, review date, optional successor, and a canonical digest.
  Decision input fact `store_valid` is boolean.
  Decision input fact `active_capsule_valid` is boolean.
  Decision input fact `matching_active_capsule_count` is integer.
  Decision input fact `has_matching_active_capsule` is boolean.
  Decision input fact `missing_obligation_count` is integer.
  Decision input fact `unclassified_changed_paths` is array.
  Decision output facts are `route` and `review_reasons`.
- API contract: `factory judgment propose|promote|reconsider|status|safety-case`.
  `safety-case` is analysis-only and

## CONSTITUTION DIGEST: one task only; read ONLY listed files; tests ship with code; never touch skeleton/; never add deps without ADR; never leave stubs; decision logic goes to the factory, not inline; stop and ask on ambiguity.

## Definition of done
Run: `python -m pytest tests/test_judgment.py -q` — must pass. Then STOP and report the diff summary.
