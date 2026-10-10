# Plan: openvsx-cadence-exception
Spec: specs/openvsx-cadence-exception.md (draft; implementation scope explicitly authorized by maintainer)
Architect verdict: PASS | keep normal cadence authoritative; allow only an exact source-bound exception after protected publish authorization

## Logical decomposition (phases)
1. Version the adapter to 1.1.3 and describe the actual changes since the 1.1.0 tag.
2. Add a narrow exception envelope to preflight and wire it only into explicitly publishing Open VSX runs after environment authorization.
3. Verify positive and adversarial cases, workflow integrity, architecture health, full relevant CI, and exact candidate package identity.
4. Obtain specialty AI review, merge only after required checks, tag the exact merge commit, publish, and verify the public Open VSX version read-back.

## Tasks (atomic — each independently shippable)
- [x] T1 | slice=editors/vscode | files=editors/vscode/package.json,editors/vscode/package-lock.json,editors/vscode/changelog.md | verify=`npm test` | Bump VS Code package/lock to 1.1.3 and add truthful release notes.
- [x] T2 | slice=factoryline | files=factoryline/release_candidate.py,factoryline/cli_release.py,tests/test_release_candidate.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin tests/test_release_candidate.py tests/test_release_integrity.py tests/test_publication_metadata.py` | Validate a time-bounded exception against exact candidate identity without changing normal cadence behavior; 101 targeted tests pass.
- [x] T3 | slice=.github/workflows | files=.github/workflows/openvsx.yml,tests/test_release_integrity.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -p pytest_asyncio.plugin tests/test_release_candidate.py tests/test_release_integrity.py tests/test_publication_metadata.py` | Expose the exception only after the protected publish authorization and preserve the sealed receipt; static workflow checks are included in the 101 passing tests.
- [x] T4 | slice=.factory | files=.factory/openvsx-release-workflow-contract.json,.factory/openvsx-release-workflow-observations.json | verify=`python -m factoryline.cli audit workflows --root . --contract .factory/openvsx-release-workflow-contract.json --observations .factory/openvsx-release-workflow-observations.json --json` | Record hash-bound workflow QA after implementation and before PR review; local audit state PASS.

Remote CI, final specialty AI review, merge, protected environment approval, and provider publication remain release gates; local PASS receipts do not satisfy them.

## 2026-10-10 approved renewal
Maintainer explicitly authorized a new one-time 1.1.3 exception and the scoped workflow update. Retire the 1.1.1 exception. Bind this approval to vscode-v1.1.3+build.1, preserving the original vscode-v1.1.3 tag. No adapter source or normal release budget changes. Current checks must be rerun; the historical results above are not evidence for this renewal.
