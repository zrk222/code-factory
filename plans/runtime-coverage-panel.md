# Plan: runtime-coverage-panel
Spec: specs/runtime-coverage-panel.md
Implementation status: IN PROGRESS
Architect verdict: PASS (read-only coverage projection; no test execution or release authority)

## Logical decomposition
1. Parse bounded Coverage.py JSON, validate statement/branch arithmetic and contained paths, and optionally verify a local source-hash receipt.
2. Add summary projection and token-protected detail API to Graph Ops.
3. Add actionable statement/branch/module views with explicit evidence states.
4. Generate artifacts in one existing CI matrix leg and in the local full-suite runner.
5. Bind full-suite evidence and show only the measured candidate result in previews.

## Tasks (atomic — one directory slice per task)
- [x] T1 | slice=factoryline | files=factoryline/runtime_coverage.py | verify=`rtk proxy python -m py_compile factoryline/runtime_coverage.py` | implement strict version-7 JSON validation, arithmetic aggregation, source-bounded locations, containment, exact source inventory, current commit/worktree binding, and explicitly unauthenticated local/CI receipt handling.
- [x] T2 | slice=tests | files=tests/test_runtime_coverage.py | verify=`rtk proxy powershell -NoProfile -Command "$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p pytest_asyncio.plugin -q tests/test_runtime_coverage.py"` | add behavioral valid, missing, malformed, oversize, inconsistent, escaped-path, out-of-range-location, truncation, current-commit, stale-time, and source-hash-binding tests.
- [x] T3 | slice=factoryline | files=factoryline/graph_ops.py | verify=`rtk proxy python -m py_compile factoryline/graph_ops.py` | add runtime coverage summary to the read-only graph payload without file details.
- [x] T4 | slice=factoryline | files=factoryline/studio.py | verify=`rtk proxy python -m py_compile factoryline/studio.py` | add token-protected `/api/coverage-report` details route.
- [x] T5 | slice=factoryline | files=factoryline/graph_ops.html | verify=`rtk proxy python -c "from pathlib import Path;p=Path('factoryline/graph_ops.html').read_text().lower();assert all(s in p for s in ['runtime statement coverage','runtime branch coverage','candidate binding']);print('UI labels PASS')"` | render separate statement and branch values, module rows, missing gaps and explicit limits using safe DOM text nodes.
- [x] T6 | slice=tests | files=tests/test_graph_ops.py,tests/test_studio.py | verify=`rtk proxy powershell -NoProfile -Command "$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p pytest_asyncio.plugin -q tests/test_graph_ops.py tests/test_studio.py"` | verify graph summary, token denial/grant, observed module details, and accessible UI evidence labels.
- [x] T7 | slice=pyproject.toml | files=pyproject.toml | verify=`rtk proxy python -c "import tomllib;tomllib.load(open('pyproject.toml','rb'));print('pyproject parse PASS')"` | add pytest-cov 7.x to development dependencies only.
- [x] T8 | slice=.github/workflows | files=.github/workflows/ci.yml | verify=`rtk proxy python -c "from pathlib import Path;p=Path('.github/workflows/ci.yml').read_text();assert 'coverage.json' in p and 'coverage.xml' in p and 'coverage.run.json' in p and 'include-hidden-files: true' in p and 'matrix.python == \'3.11\'' in p;print('CI coverage contract PASS')"` | run branch-aware reporting in the existing Ubuntu Python 3.11 matrix leg and upload all four required `.factory/test-reports` artifacts.
- [ ] T9 | slice=tools/workflow-audit | files=tools/workflow-audit/run-attribution-tests.ps1,tools/workflow-audit/write-ci-runtime-coverage.py,tools/workflow-audit/bind-local.py | verify=`rtk proxy python -m py_compile tools/workflow-audit/bind-local.py tools/workflow-audit/write-ci-runtime-coverage.py` | write exact-command local and clean-runner CI receipts, bind current commit/worktree state, normalized report interval, source hashes and artifact digests.
- [x] T10 | slice=tests | files=tests/test_attribution_binder.py | verify=`rtk proxy powershell -NoProfile -Command "$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'; python -m pytest -p pytest_asyncio.plugin -q tests/test_attribution_binder.py"` | reject missing, mismatched, changed-source, failing and stale coverage evidence; verify exact command and actual Git HEAD/worktree binding.
- [ ] T11 | slice=README.md | files=README.md | verify=`rtk proxy git diff --check; rtk proxy python -c "from pathlib import Path;p=Path('README.md').read_text(encoding='utf-8');assert all(s in p for s in ['runtime statement coverage','runtime branch coverage','ForgeLine static test-intent']);print('README metric separation PASS')"` | state measured line/branch coverage separately from static attribution, only after the full current suite run.
- [ ] T12 | slice=deploy/huggingface | files=deploy/huggingface/README.md,deploy/huggingface/index.html | verify=`rtk proxy git diff --check; rtk proxy python -c "from pathlib import Path;p=' '.join(Path(x).read_text(encoding='utf-8') for x in ['deploy/huggingface/README.md','deploy/huggingface/index.html']);assert all(s in p for s in ['runtime statement coverage','runtime branch coverage','ForgeLine static test-intent']);print('HF preview metric separation PASS')"` | state measured line/branch coverage separately from static attribution, only after the full current suite run.
- [ ] T13 | slice=tools/workflow-audit | files=tools/workflow-audit/attribution-final.log,tools/workflow-audit/attribution-full-suite.run.json | verify=`rtk proxy powershell -NoProfile -ExecutionPolicy Bypass -File tools/workflow-audit/run-attribution-tests.ps1 -Mode full` | run the full suite with branch coverage and validate report hashes and exact run identity.
- [ ] T14 | slice=.factory | files=.factory/workflow-audit-observations.json | verify=`rtk proxy python tools/workflow-audit/bind-local.py` | record and validate current runtime coverage observations in workflow-audit evidence.

## Risk controls
- The dashboard parses local evidence only; it never runs code, installs plugins, or contacts a provider.
- Runtime coverage, JUnit outcomes, and ForgeLine static test-intent attribution remain distinct evidence classes.
- Local and GitHub Actions receipts prove declared hash consistency only; neither is authenticated or CI-signed in this change.
- No coverage percentage is presented as assertion strength, defect absence, certification, or release approval.
