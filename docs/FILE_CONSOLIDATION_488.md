# Physical consolidation: 488 tracked Python files

Status: scoped cleanup verified by independent ECC review. The global goal remains incomplete; this report does not establish merge or release readiness.

## Changes

- 590 → 488 tracked Python files: 102 test modules physically removed after moving every test into existing owners. No new Python module or compatibility shim.
- All 7,801 collected cases map one-to-one, with zero missing, extra or duplicate cases.
- 148 command comparisons preserve their original test cohorts; assertions, pass counts and timeouts are unchanged.
- 64 unrelated work-in-progress paths were preserved byte-for-byte. Another 24 untracked Python files are outside this committed-inventory milestone.

## Verification

The tested Git tree is `71e4b1568dcfcbbd76d3b8fbe1eabd73ddae4807`, based on `60976f341bb7e121d010f39da338849c37f7310b`.

| Check | Result |
| --- | --- |
| Affected execution | 2,259 passed; 5 existing skips; 174.63 seconds |
| Full collection | 7,801 → 7,801; exact mapped case multiset |
| Real Rich dead tests | All 3 remain SHADOWED at MEDIUM |
| Historical security controls | 13/13 retain original code, location and severity |
| Metadata | 106 JSON/YAML files parse; noncommand settings unchanged |
| Architecture | BLOCKED: 488 > 460 Python files; 190 > 129 core modules |

## Precision

New held-out precision is **NOT MEASURED**. The externally reported 2 HOLLOW, 41 WEAK, 154 UNKNOWN and 3 SHADOWED findings are counts, not a precision score. The social38 family remains 38 active / 0 cleared. This structural change makes no detector accuracy claim.

## Remaining failures

- The paired metadata profile has the same public-docstring failure on baseline and candidate: 202 source callables lack required docstrings.
- An existing readiness smoke expects 90 passes but selects 1,633 baseline cases. Its assertion is preserved.
- Three older smoke selectors were already absent on the baseline: `test_hosted_console.py`, `test_public_docstrings.py`, and `test_runtime_audit_native_engines.py`. They are disclosed separately from the repaired consolidation paths.
- Three original modules with no annotations acquire future-annotations code flags when merged. Those reviewed semantic exceptions remain disclosed.
- Independent ECC review passed for the cleanup scope. The full suite has not been claimed green.

The [machine-readable report](evidence/file-consolidation-488.json) contains ownership maps, candidate hashes and exact evidence digests.
