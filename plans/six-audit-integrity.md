# Plan: Six audit integrity
Spec: specs/six-audit-integrity.md
Architect verdict: PASS
- [x] T1 | slice=factoryline | files=factoryline/runtime_audit.py,factoryline/runtime_audit_integrity.py | verify=`python -m pytest -q tests/test_runtime_audit.py tests/test_runtime_audit_integrity.py` | Reject ambiguous joins and supply precise repair routing.

## Outcome
All six audit lanes now reject ambiguous execution collections instead of overwriting duplicate IDs.
Per-lane repair guidance distinguishes incomplete/hollow audit evidence from application defects,
includes both signed replay commands and preserves human release authority.
The seven runtime-audit test files passed 30 tests. Scoped SpecLine drift, requirement mutation,
ForgeLine review, architecture, stub rejection and smoke checks passed.
No new external engine runs, benchmark speedup, authenticated evidence or exhaustive audit coverage is claimed.
