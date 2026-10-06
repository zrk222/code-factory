# Open VSX 1.1.1 verification observations

Observed locally on Windows, CPython 3.11.9, 2026-10-06.

- `factory doctor --strict --json`: `ok=true`; required modules installed, commands and provenance checks pass.
- `python -m factoryline.cli architecture health --root . --strict --json`: `decision=HEALTHY`; Python files 460/460; the strict file cap is preserved. The normal core release cadence remains blocked until 2026-10-11T14:45:53Z; the separately approved Open VSX exception does not modify that policy.
- `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin tests/test_release_candidate.py tests/test_release_integrity.py tests/test_publication_metadata.py`: 101 passed.
- `ruff check --select C901 factoryline tests`: passed; the cadence preflight helpers keep the configured complexity threshold intact.
- `ruff check factoryline/release_candidate.py tests/test_publication_metadata.py`: passed.
- `ruff format --check factoryline/release_candidate.py tests/test_publication_metadata.py`: passed.
- Previous hosted CI on commit `06162731fac571a62cb9112461ab21615701874e` failed due to the stale 1.1.0 assertion in `tests/test_publication_metadata.py` and a C901 finding in the candidate-preflight orchestration. Both are corrected in the current candidate; hosted CI must rerun on the pushed commit before merge or release.
- VS Code `npm test` and `npm run compile` passed before these Python-only corrections; the package and lockfile are unchanged by this correction.
- Provider publication has not been run. The GitHub `openvsx` environment requires approval; the current account is its only listed reviewer with self-review disabled, so publication remains blocked until an eligible environment approver authorizes the run.
- The project workflow audit checks candidate hash and evidence completeness. Its PASS is not a CI, security, merge, approval, or publication result.
