# Plan: perf-optimization-appforge-revenueforge-prestige
Spec: specs/perf-optimization-appforge-revenueforge-prestige.md
Architect verdict: PASS (bounded performance changes, byte/output parity required)

## Logical decomposition (phases)
1. Add byte-equality fast paths to AppForge and RevenueForge deterministic output writes.
2. Replace repeated Prestige term regex scans with a boundary-equivalent string search.
3. Split the security-scan coordinator and tenant-binding validation until every
   scanner path stays within the existing complexity limit; keep the hard scan
   ceiling at 460.
4. Re-run focused tests, hash-bound workflow audit, package checks, and paired benchmarks.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [x] T1 | slice=factoryline | files=factoryline/revenue_evidence.py,factoryline/appforge_design.py,tests/test_appforge_design.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q -p pytest_asyncio.plugin tests/test_appforge_design.py` | Skip identical AppForge artifact replacements.
- [x] T2 | slice=factoryline | files=factoryline/revenueforge.py,tests/test_revenueforge.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q -p pytest_asyncio.plugin tests/test_revenueforge.py` | Skip identical RevenueForge bundle replacements.
- [x] T3 | slice=prestige_design | files=prestige_design/purpose.py,tests/test_prestige.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q -p pytest_asyncio.plugin tests/test_prestige.py` | Preserve Unicode boundary counts with fewer long-text scans.
- [x] T4 | slice=security-audit | files=factoryline/review_audits.py,tests/test_review_audits.py | verify=`ruff check --select C901 --config 'lint.mccabe.max-complexity=10' factoryline/review_audits.py; python -m pytest -q -p pytest_asyncio.plugin tests/test_review_audits.py` | Keep scanner coordination and tenant contract parsing under the complexity ceiling without changing scan receipts; preserve the hard 460-source cap.
- [x] T5 | slice=quality-policy | files=architecture-policy.json,tests/test_benchmark_lab.py,docs/adr/ADR-20261005-python-source-ceiling.md | verify=`factory architecture health --strict --json; python tests/test_benchmark_lab.py --prestige-root <prestige-checkout> --runs 11` | Keep the tracked Python inventory at or below 460 and retain a reproducible paired benchmark runner.
