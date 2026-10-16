# Plan: borrowed-resource-contract
Spec: specs/borrowed-resource-contract.md
Architect verdict: PASS

## Logical decomposition (phases)
1. Extract the implementation-contract AST logic and shared closure into a dedicated module, preserving `intent_quality` compatibility imports.
2. Predeclare and pin the extracted module budget without changing any existing cap or total-inventory/core budget.
3. Move the three privacy tests intact into the compliance test module so the tracked Python inventory remains fixed.
4. Prove focused positive/negative contracts, unchanged source bytes for the retained Click file, unchanged privacy assertions, and architecture pin behavior.

## Tasks (atomic — each independently shippable)
<!-- Rules enforced by `specline tasks`: one slice each, <=4 files,
     explicit verify command, no forward references. -->
- [ ] T1 | slice=factoryline | files=factoryline/implementation_audit.py,factoryline/intent_quality.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 rtk proxy python -m pytest -p pytest_asyncio.plugin tests/test_review_integrity.py -k "borrowed_resource or explicit_extension_contract or unfinished_and_ambiguous_methods_remain or null_io_protocol_behavior"` | Extract the implementation AST contract helpers; add the bounded no-close contract and preserve `intent_quality` compatibility exports.
- [ ] T2 | slice=tests | files=tests/test_review_integrity.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 rtk proxy python -m pytest -p pytest_asyncio.plugin tests/test_review_integrity.py -k "borrowed_resource or explicit_extension_contract or unfinished_and_ambiguous_methods_remain or null_io_protocol_behavior"` | Preserve the retained Click no-op classification and prove generic positives plus adversarial negative controls.
- [ ] T3 | slice=architecture-policy.json | files=architecture-policy.json | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 rtk proxy python -m pytest -p pytest_asyncio.plugin tests/test_architecture_health.py -k "pinned or implementation_audit"` | Predeclare the new module cap while preserving every existing cap and total inventory/core budgets.
- [ ] T4 | slice=factoryline | files=factoryline/architecture_guard.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 rtk proxy python -m pytest -p pytest_asyncio.plugin tests/test_architecture_health.py -k "pinned or implementation_audit"` | Update the exact pinned digest for the added module budget.
- [ ] T5 | slice=tests | files=tests/test_architecture_health.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 rtk proxy python -m pytest -p pytest_asyncio.plugin tests/test_architecture_health.py -k "pinned or implementation_audit"` | Add positive cap and negative mutation controls for the new budget, while asserting 460 files and 129 core modules.
- [ ] T6 | slice=tests | files=tests/test_compliance.py,tests/test_privacy.py | verify=`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 rtk proxy python -m pytest -p pytest_asyncio.plugin tests/test_compliance.py -k "merkle or optional_cryptographic"` | Move all three privacy tests and imports into compliance tests without changing cases or assertions; remove the old test file.
